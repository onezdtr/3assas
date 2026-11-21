mod control;
mod dns;
mod event;
mod geo;
mod rules;
mod store;

use std::{
    collections::{HashMap, HashSet},
    mem::MaybeUninit,
    net::IpAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use libbpf_rs::{
    MapCore, MapFlags, RingBufferBuilder,
    skel::{OpenSkel, Skel, SkelBuilder},
};

use event::{EV_BLOCKED, EV_CLOSE, EV_CONNECT, RawEvent};

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}
use tracer::{TracerSkel, TracerSkelBuilder};

/// What the shared ring buffer carries: a connection event or a raw DNS answer.
enum Msg {
    Conn(RawEvent),
    Dns(Vec<u8>),
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Opts {
    json: bool,
    all: bool,
    data: PathBuf,
    db: Option<PathBuf>,
    rules: PathBuf,
    cmd: Option<(String, Option<String>)>,
}

fn opts() -> Result<Opts> {
    let mut o = Opts {
        json: false,
        all: false,
        data: PathBuf::from("data"),
        db: None,
        rules: PathBuf::from(rules::DEFAULT_FILE),
        cmd: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => o.json = true,
            "--all" => o.all = true,
            "--data" => o.data = args.next().context("--data needs a directory")?.into(),
            "--db" => o.db = Some(args.next().context("--db needs a file")?.into()),
            "--rules" => o.rules = args.next().context("--rules needs a file")?.into(),
            "block" | "unblock" | "blocked" => o.cmd = Some((a.clone(), args.next())),
            "-h" | "--help" => {
                println!(
                    "usage: 3assas [--json] [--all] [--data DIR] [--db FILE] [--rules FILE]\n       3assas block PATH | unblock PATH | blocked\n  block   deny network sockets to an executable (kept in /etc/3assas/blocked, applied live)\n  --db    service mode: store events in SQLite, print nothing\n  --json  one JSON object per line\n  --all   include loopback traffic\n  --data  directory with dbip-country.csv.gz and ip2asn.tsv.gz (default: ./data)"
                );
                std::process::exit(0);
            }
            _ => bail!("unknown argument {a} (see --help)"),
        }
    }
    Ok(o)
}

/// Optional enrichment: a missing file costs labels, not the trace.
fn load(path: &Path, f: fn(&Path) -> Result<geo::Ranges>) -> Option<geo::Ranges> {
    f(path)
        .map_err(|e| eprintln!("warning: {e:#} (labels disabled)"))
        .ok()
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        // 100.64.0.0/10 = carrier-grade NAT, also Tailscale
        IpAddr::V4(a) => {
            a.is_private()
                || a.is_link_local()
                || (a.octets()[0] == 100 && a.octets()[1] & 0xc0 == 64)
        }
        IpAddr::V6(a) => {
            (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn human(b: u64) -> String {
    const U: [&str; 4] = ["B", "kB", "MB", "GB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1000.0 && i < 3 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn clock() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as libc::time_t;
    let mut tm = MaybeUninit::<libc::tm>::zeroed();
    // SAFETY: localtime_r writes into the provided tm and is thread-safe.
    let tm = unsafe {
        libc::localtime_r(&now, tm.as_mut_ptr());
        tm.assume_init()
    };
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// Executable behind a pid. Cached so close events still resolve after the process exits.
struct Exes(HashMap<(u32, String), String>);

impl Exes {
    fn get(&mut self, tgid: u32, comm: &str) -> String {
        if let Some(p) = self.0.get(&(tgid, comm.to_owned())) {
            return p.clone();
        }
        let Ok(p) = std::fs::read_link(format!("/proc/{tgid}/exe")) else {
            return format!("[{comm}]");
        };
        // shortcut: wholesale reset bounds memory but drops warm entries, switch to an LRU if it shows up in profiles
        if self.0.len() > 4096 {
            self.0.clear();
        }
        let p = p.to_string_lossy().into_owned();
        self.0.insert((tgid, comm.to_owned()), p.clone());
        p
    }
}

/// Policy of the control socket. Only "block": unblocking stays with `sudo 3assas unblock`, so a
/// compromised user account cannot free a program you cut off. A non-root caller may block only
/// executables that ran under its own uid, so it cannot cut off another user's or a system service.
fn control_request(db: &store::Store, rules_file: &Path, uid: u32, req: &str) -> String {
    let Some(path) = req.strip_prefix("block ") else {
        return "error: unknown request".into();
    };
    if uid != 0 && !db.seen(path, uid).unwrap_or(false) {
        return "error: you can only block programs that ran as you".into();
    }
    match rules::add(rules_file, path) {
        Ok(true) => format!("ok blocked {path}"),
        Ok(false) => format!("ok already blocked {path}"),
        Err(e) => format!("error: {e:#}"),
    }
}

/// Mirrors the block list file into the kernel map whenever the file changes.
#[derive(Default)]
struct Blocker {
    seen: Option<(SystemTime, u64)>,
    applied: std::collections::BTreeSet<String>,
}

impl Blocker {
    fn sync(&mut self, file: &Path, map: &libbpf_rs::Map, flag: Option<&mut tracer::types::bss>) {
        let stamp = std::fs::metadata(file).ok().map(|m| (m.modified().unwrap_or(UNIX_EPOCH), m.len()));
        if stamp == self.seen && self.seen.is_some() {
            return;
        }
        self.seen = stamp;
        let want = rules::read(file);
        for p in self.applied.difference(&want) {
            if let Some(k) = rules::key(p) {
                let _ = map.delete(&k);
            }
        }
        let mut applied = std::collections::BTreeSet::new();
        for p in &want {
            match rules::key(p).map(|k| map.update(&k, &[1u8], MapFlags::ANY)) {
                Some(Ok(())) => {
                    applied.insert(p.clone());
                }
                _ => eprintln!("warning: cannot block {p}"),
            }
        }
        if applied != self.applied {
            eprintln!("block list: {} program(s)", applied.len());
        }
        if let Some(f) = flag {
            // SAFETY: f points into the BPF program's mmapped .bss; a volatile store is what the kernel side reads.
            unsafe { std::ptr::write_volatile(&mut f.blocking, !applied.is_empty() as u32) };
        }
        self.applied = applied;
    }
}

#[derive(Default)]
struct Stat {
    conns: u64,
    up: u64,
    down: u64,
    dests: HashSet<IpAddr>,
    countries: HashSet<String>,
}

/// The socket blocker needs the BPF LSM (`bpf` in the kernel's LSM list) and Linux 6.12+ kfuncs.
/// Without them everything else still loads: tracing must not depend on blocking.
fn load_bpf<'o>(obj: &'o mut MaybeUninit<libbpf_rs::OpenObject>, blocker: bool) -> Result<TracerSkel<'o>> {
    let mut open = TracerSkelBuilder::default().open(obj)?;
    if !blocker {
        open.progs.on_socket_create.set_autoload(false);
    }
    Ok(open.load()?)
}

fn main() -> Result<()> {
    let o = opts()?;
    if let Some((cmd, arg)) = &o.cmd {
        return rules::command(cmd, arg.as_deref(), &o.rules);
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("3assas loads eBPF programs into the kernel: run it as root (sudo)");
    }
    let countries = load(&o.data.join("dbip-country.csv.gz"), geo::countries);
    let owners = load(&o.data.join("ip2asn.tsv.gz"), geo::owners);

    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let mut obj = MaybeUninit::uninit();
    let mut fallback = MaybeUninit::uninit();
    let mut can_block = lsm.split(',').any(|m| m.trim() == "bpf");
    let mut skel = match load_bpf(&mut obj, can_block) {
        Ok(s) => s,
        Err(e) if can_block => {
            eprintln!("warning: blocking disabled, the kernel refused the blocker ({e:#}); needs Linux 6.12+");
            can_block = false;
            load_bpf(&mut fallback, false).context("load BPF program")?
        }
        Err(e) => return Err(e.context("load BPF program")),
    };
    if !can_block {
        eprintln!("warning: blocking disabled: the BPF LSM is not active (add bpf to the lsm= boot parameter)");
    }
    skel.attach().context("attach BPF program")?;
    // The DNS watcher needs a cgroup v2 root; without one, connections just come unnamed.
    let _dns = std::fs::File::open("/sys/fs/cgroup")
        .map_err(anyhow::Error::from)
        .and_then(|cg| Ok(skel.progs.on_ingress.attach_cgroup(cg.as_raw_fd())?))
        .map_err(|e| eprintln!("warning: DNS watcher not attached ({e:#}), domains disabled"))
        .ok();

    // Taken out before the ring buffer borrows the skeleton's maps.
    let mut blocking_flag = skel.maps.bss_data.take();
    let mut blocker = Blocker::default();

    let (tx, rx) = mpsc::channel();
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.events, move |data| {
        // One ring for both kinds keeps their order: a DNS answer always arrives before the connect it enables.
        let msg = if data.len() == std::mem::size_of::<RawEvent>() {
            RawEvent::parse(data).map(Msg::Conn)
        } else {
            dns::payload(data).map(|p| Msg::Dns(p.to_vec()))
        };
        if let Some(m) = msg {
            let _ = tx.send(m);
        }
        0
    })?;
    let rb = rb.build()?;

    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
    }
    if !o.json && o.db.is_none() {
        eprintln!("3assas: watching outbound connections, Ctrl-C for the summary");
    }

    let mut store = o.db.as_deref().map(store::Store::open).transpose().context("open database")?;
    // Service mode only: the policy below needs the event history.
    let control = (store.is_some() && can_block)
        .then(|| control::Control::bind(Path::new(control::SOCK)))
        .transpose()
        .map_err(|e| eprintln!("warning: control socket unavailable ({e:#}): blocking from the agent disabled"))
        .ok()
        .flatten();
    let read_drops = || -> u64 {
        skel.maps
            .drops
            .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .unwrap_or_default()
            .iter()
            .map(|c| u64::from_ne_bytes(c[..8].try_into().unwrap()))
            .sum()
    };
    let mut exes = Exes(HashMap::new());
    let mut names = dns::Names::default();
    let mut stats: HashMap<String, Stat> = HashMap::new();
    let mut batch = Vec::new();
    let mut last_tick = 0;
    while !STOP.load(Ordering::Relaxed) {
        // EINTR on Ctrl-C is expected: the loop condition handles it.
        let _ = rb.poll(Duration::from_millis(200));
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        if can_block {
            blocker.sync(&o.rules, &skel.maps.blocked, blocking_flag.as_deref_mut());
        }
        for m in rx.try_iter() {
            let e = match m {
                Msg::Conn(e) => e,
                Msg::Dns(p) => {
                    names.learn(&p);
                    continue;
                }
            };
            let ip = e.addr();
            let domain = names.get(ip).map(String::from);
            let blocked = e.kind == EV_BLOCKED; // refused at socket(), before any address exists
            if !blocked && !o.all && (ip.is_loopback() || ip.is_unspecified()) {
                continue;
            }
            let comm = e.comm();
            let exe = exes.get(e.tgid, &comm);
            let (owner, cc) = if blocked {
                (None, None)
            } else if is_local(ip) {
                (Some("local network"), None)
            } else {
                (
                    owners.as_ref().and_then(|t| t.get(ip)),
                    countries.as_ref().and_then(|t| t.get(ip)),
                )
            };
            let r = store::Row {
                t_ms: now_ms,
                kind: match e.kind {
                    EV_CONNECT => "connect",
                    EV_CLOSE => "close",
                    EV_BLOCKED => "blocked",
                    _ => "udp",
                },
                proto: e.proto(),
                pid: e.tgid,
                uid: e.uid,
                comm,
                exe,
                ip: if blocked { String::new() } else { ip.to_string() },
                port: e.dport,
                owner: owner.map(String::from),
                country: cc.map(String::from),
                sent: e.bytes_sent,
                recv: e.bytes_recv,
                duration_ms: e.duration_ns / 1_000_000,
                failed: e.failed(),
                domain,
            };

            if store.is_some() {
                batch.push(r);
                continue;
            }
            let s = stats.entry(r.exe.clone()).or_default();
            if e.kind != EV_CLOSE && !blocked {
                s.conns += 1;
                s.dests.insert(ip);
                s.countries.extend(r.country.clone());
            }
            s.up += r.sent;
            s.down += r.recv;

            if o.json {
                let v = serde_json::json!({
                    "time_ms": r.t_ms, "event": r.kind, "proto": r.proto, "pid": r.pid, "uid": r.uid,
                    "comm": r.comm, "exe": r.exe, "ip": r.ip, "port": r.port, "domain": r.domain, "owner": r.owner,
                    "country": r.country, "bytes_sent": r.sent, "bytes_recv": r.recv,
                    "duration_ms": r.duration_ms, "failed": r.failed,
                });
                println!("{v}");
                continue;
            }
            let name = Path::new(&r.exe)
                .file_name()
                .map_or(r.exe.clone(), |n| n.to_string_lossy().into_owned());
            let dest = match ip {
                _ if blocked => "-".to_owned(),
                IpAddr::V6(_) => format!("[{ip}]:{}", e.dport),
                _ => format!("{ip}:{}", e.dport),
            };
            let label = [r.domain.as_deref(), owner, cc]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
                .join(" · ");
            let detail = match e.kind {
                EV_CONNECT => label,
                EV_BLOCKED => "blocked: socket refused".to_owned(),
                EV_CLOSE if e.failed() => {
                    format!("no answer after {:.1}s", e.duration_ns as f64 / 1e9)
                }
                EV_CLOSE => format!(
                    "{:.1}s  ↑{}  ↓{}",
                    e.duration_ns as f64 / 1e9,
                    human(e.bytes_sent),
                    human(e.bytes_recv)
                ),
                _ => format!("↑{}  {label}", human(e.bytes_sent)),
            };
            let arrow = match e.kind {
                EV_CONNECT => "→",
                EV_BLOCKED => "⊘",
                EV_CLOSE if e.failed() => "✗",
                EV_CLOSE => "✓",
                _ => "↗",
            };
            println!(
                "{}  {arrow} {}  {name:<18} {dest:<42} {detail}",
                clock(),
                e.proto()
            );
        }
        if let (Some(c), Some(db)) = (&control, &store) {
            c.serve(|uid, req| {
                let reply = control_request(db, &o.rules, uid, req);
                eprintln!("control: uid {uid}: {req} -> {reply}");
                reply
            });
        }
        if let Some(db) = &mut store {
            // A failed write is logged and retried with the next batch instead of killing the tracer.
            if !batch.is_empty() {
                match db.insert(&batch) {
                    Ok(()) => batch.clear(),
                    Err(err) => eprintln!("database write failed ({} events kept): {err:#}", batch.len()),
                }
                // Bounded memory if the disk stays broken: keep the newest events.
                if batch.len() > 50_000 {
                    batch.drain(..batch.len() - 50_000);
                }
            }
            if now_ms - last_tick >= 60_000 {
                last_tick = now_ms;
                if let Err(err) = db.tick(now_ms, read_drops()) {
                    eprintln!("database housekeeping failed: {err:#}");
                }
            }
        }
    }

    let drops = read_drops();
    if o.json || store.is_some() {
        return Ok(());
    }
    let mut rows: Vec<_> = stats.into_iter().collect();
    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.up + s.down));
    eprintln!(
        "\n{:<40} {:>6} {:>6} {:>10} {:>10}  countries",
        "program", "conns", "dests", "sent", "received"
    );
    for (exe, s) in rows {
        let mut cc: Vec<_> = s.countries.into_iter().collect();
        cc.sort();
        eprintln!(
            "{exe:<40} {:>6} {:>6} {:>10} {:>10}  {}",
            s.conns,
            s.dests.len(),
            human(s.up),
            human(s.down),
            cc.join(" ")
        );
    }
    if drops > 0 {
        eprintln!("\nwarning: {drops} events lost (buffers full), counts above are a lower bound");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_policy_only_blocks_your_own_programs() {
        let mut db = store::Store::open(Path::new(":memory:")).unwrap();
        db.insert(&[store::Row {
            t_ms: 1, kind: "connect", proto: "TCP", pid: 1, uid: 1000, comm: "upd".into(),
            exe: "/home/me/.cache/x/upd".into(), ip: "1.2.3.4".into(), port: 443, owner: None,
            country: None, sent: 0, recv: 0, duration_ms: 0, failed: false, domain: None,
        }])
        .unwrap();
        let file = std::env::temp_dir().join(format!("3assas-policy-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let ask = |uid, req| control_request(&db, &file, uid, req);

        assert!(ask(1001, "block /home/me/.cache/x/upd").starts_with("error"), "another user's program");
        assert!(ask(1000, "block /usr/bin/curl").starts_with("error"), "never ran as this user");
        assert!(ask(1000, "unblock /home/me/.cache/x/upd").starts_with("error"), "no unblocking here");
        assert_eq!(ask(1000, "block /home/me/.cache/x/upd"), "ok blocked /home/me/.cache/x/upd");
        assert!(ask(1000, "block /home/me/.cache/x/upd").starts_with("ok already"));
        assert!(ask(0, "block /usr/lib/systemd/systemd-resolved").starts_with("error"), "vital, even for root");
        assert_eq!(rules::read(&file).len(), 1);
        let _ = std::fs::remove_file(&file);
    }
}
