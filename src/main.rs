mod event;
mod geo;
mod store;

use std::{
    collections::{HashMap, HashSet},
    mem::MaybeUninit,
    net::IpAddr,
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

use event::{EV_CLOSE, EV_CONNECT, RawEvent};

mod tracer {
    include!(concat!(env!("OUT_DIR"), "/tracer.skel.rs"));
}
use tracer::TracerSkelBuilder;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Opts {
    json: bool,
    all: bool,
    data: PathBuf,
    db: Option<PathBuf>,
}

fn opts() -> Result<Opts> {
    let mut o = Opts {
        json: false,
        all: false,
        data: PathBuf::from("data"),
        db: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => o.json = true,
            "--all" => o.all = true,
            "--data" => o.data = args.next().context("--data needs a directory")?.into(),
            "--db" => o.db = Some(args.next().context("--db needs a file")?.into()),
            "-h" | "--help" => {
                println!(
                    "usage: 3assas [--json] [--all] [--data DIR] [--db FILE]\n  --db    service mode: store events in SQLite, print nothing\n  --json  one JSON object per line\n  --all   include loopback traffic\n  --data  directory with dbip-country.csv.gz and ip2asn.tsv.gz (default: ./data)"
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

#[derive(Default)]
struct Stat {
    conns: u64,
    up: u64,
    down: u64,
    dests: HashSet<IpAddr>,
    countries: HashSet<String>,
}

fn main() -> Result<()> {
    let o = opts()?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("3assas loads eBPF programs into the kernel: run it as root (sudo)");
    }
    let countries = load(&o.data.join("dbip-country.csv.gz"), geo::countries);
    let owners = load(&o.data.join("ip2asn.tsv.gz"), geo::owners);

    let mut obj = MaybeUninit::uninit();
    let mut skel = TracerSkelBuilder::default()
        .open(&mut obj)?
        .load()
        .context("load BPF program")?;
    skel.attach().context("attach BPF program")?;

    let (tx, rx) = mpsc::channel();
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.events, move |data| {
        if let Some(e) = RawEvent::parse(data) {
            let _ = tx.send(e);
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
    let mut stats: HashMap<String, Stat> = HashMap::new();
    let mut batch = Vec::new();
    let mut last_tick = 0;
    while !STOP.load(Ordering::Relaxed) {
        // EINTR on Ctrl-C is expected: the loop condition handles it.
        let _ = rb.poll(Duration::from_millis(200));
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        for e in rx.try_iter() {
            let ip = e.addr();
            if !o.all && (ip.is_loopback() || ip.is_unspecified()) {
                continue;
            }
            let comm = e.comm();
            let exe = exes.get(e.tgid, &comm);
            let (owner, cc) = if is_local(ip) {
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
                    _ => "udp",
                },
                proto: e.proto(),
                pid: e.tgid,
                uid: e.uid,
                comm,
                exe,
                ip: ip.to_string(),
                port: e.dport,
                owner: owner.map(String::from),
                country: cc.map(String::from),
                sent: e.bytes_sent,
                recv: e.bytes_recv,
                duration_ms: e.duration_ns / 1_000_000,
                failed: e.failed(),
            };

            if store.is_some() {
                batch.push(r);
                continue;
            }
            let s = stats.entry(r.exe.clone()).or_default();
            if e.kind != EV_CLOSE {
                s.conns += 1;
                s.dests.insert(ip);
                s.countries.extend(r.country.clone());
            }
            s.up += r.sent;
            s.down += r.recv;

            if o.json {
                let v = serde_json::json!({
                    "time_ms": r.t_ms, "event": r.kind, "proto": r.proto, "pid": r.pid, "uid": r.uid,
                    "comm": r.comm, "exe": r.exe, "ip": r.ip, "port": r.port, "owner": r.owner,
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
                IpAddr::V6(_) => format!("[{ip}]:{}", e.dport),
                _ => format!("{ip}:{}", e.dport),
            };
            let label = [owner, cc]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
                .join(" · ");
            let detail = match e.kind {
                EV_CONNECT => label,
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
