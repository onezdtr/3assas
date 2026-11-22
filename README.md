# 3assas

*"the guard" in Darija.* See which program on your Linux machine talks to whom, from inside the kernel.

![3assas web page: programs, their destinations, AI-judged alerts, live feed](docs/demo.gif)

<sub>Demo data (docs/demo/gen.py): a hidden binary in `~/.cache` uploading to a Russian host gets flagged, a browser
reaching a new CDN region does not.</sub>

```
13:41:09  → TCP  curl               140.82.121.3:443        api.github.com · GITHUB - GitHub, Inc. · GB
13:41:09  ✓ TCP  curl               140.82.121.3:443        0.2s  ↑1.9 kB  ↓548.2 kB
13:41:11  ✗ TCP  curl               192.0.2.1:81            no answer after 2.0s
13:41:11  ↗ UDP  brave              142.251.39.206:443      ↑1.2 kB  GOOGLE - Google LLC · US
```

DNS-level blockers only see names. 3assas sees every outbound TCP connection and UDP flow, attributed to the
executable that opened it: hardcoded IPs, DNS-over-HTTPS, QUIC, apps that never ask your resolver.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/onezdtr/3assas/main/get.sh | sudo sh
```

Prebuilt for x86_64 and aarch64 (glibc ≥ 2.35, Linux ≥ 5.11 with BTF, python3). The script downloads the latest
[release](https://github.com/onezdtr/3assas/releases), checks its SHA-256, puts it in `/opt/3assas` and starts both
services; run it again to update. Website: [onezdtr.github.io/3assas](https://onezdtr.github.io/3assas/).

Uninstall:

```sh
sudo systemctl disable --now 3assas 3assas-agent
sudo rm -rf /opt/3assas /usr/local/bin/3assas /usr/local/share/3assas /var/lib/3assas \
  /etc/systemd/system/3assas.service /etc/systemd/system/3assas-agent.service
rm -rf ~/.local/share/3assas   # agent history
```

## Block a program

```sh
sudo 3assas block ~/.cache/x/upd     # refused any network socket from now on
sudo 3assas unblock ~/.cache/x/upd
3assas blocked                       # the list (/etc/3assas/blocked)
```

The running service applies changes within a second, no restart. The kernel refuses the program's IPv4/IPv6
sockets at creation (`socket()` fails with `EPERM`), so TCP, UDP, QUIC and DNS lookups all stop; Unix sockets
(D-Bus, display) keep working. Programs that keep the machine online (systemd's resolver and network daemons,
NetworkManager, wpa_supplicant, sshd, tailscaled) and 3assas itself cannot be blocked.

From Telegram: alerts judged `watch` or `suspicious` come with a **Block** button. The agent has no root; it asks
the service over `/run/3assas/control.sock`, and the service checks the caller's uid with `SO_PEERCRED`: a user can
block only programs that ran as that user, never a system service, and unblocking is not offered there at all,
so a compromised account cannot free what you cut off. Give 3assas a bot of its own (BotFather): the agent reads
its updates for the button taps, only the configured chat's taps count.

## How it works

| Hook | What it catches | Cost |
|---|---|---|
| `tp_btf/inet_sock_set_state` → `SYN_SENT` | outbound TCP connect, owner pid/uid/comm | once per connection |
| `tp_btf/inet_sock_set_state` → `CLOSE` | duration, payload bytes both ways, failed handshakes | once per connection |
| `fentry/udp_sendmsg`, `udpv6_sendmsg` | UDP flows (QUIC, DNS, games) | map lookup per send, event once per flow / 30 s |
| `cgroup_skb/ingress` on the root cgroup | DNS answers (UDP from port 53), copied raw to userspace | 2 header reads per received packet |
| `lsm/socket_create` | blocks listed executables | one load per socket while the list is empty |

Design choices:
- **No per-packet path for TCP.** Byte counts are read from `tcp_sock` once at close (`bytes_sent - bytes_retrans`,
  `bytes_received` minus the FIN), not summed from `sendmsg` calls.
- **Owner captured at `SYN_SENT`.** The transition to `CLOSE` often runs in softirq context where `current` is an
  unrelated task, so the owner is stored per socket when `connect()` runs.
- **CO-RE.** Built against the running kernel's BTF (`vmlinux.h` is generated at build time), checked downcast with
  `bpf_skc_to_tcp_sock`.
- **Domains from the answers the machine already gets.** The kernel copies each DNS answer (up to 1232 bytes, the
  EDNS default) into the same ring buffer as connections, so an answer is always read before the connect it enables.
  Userspace parses it (compression pointers bounded, names limited to hostname characters: the packet comes off the
  network) and tags each address with the name that was *asked*, not the CDN alias at the end of the CNAME chain.
  Seen on loopback too, so it works behind systemd-resolved. Not seen: DNS-over-HTTPS/TLS and DNS over TCP; the
  connection then keeps its IP, owner and country.
- **Blocking by full path, decided at `socket()`.** The LSM hook gets the caller's executable
  (`bpf_get_task_exe_file`) and its path (`bpf_path_d_path`), then looks it up in a hash map the service syncs from
  `/etc/3assas/blocked`. Paths rather than inode numbers: btrfs subvolumes share one device, so `(dev, ino)` can name
  two different files. A `.bss` flag skips all of it while the list is empty. Needs the BPF LSM (`bpf` in
  `/sys/kernel/security/lsm`) and Linux 6.12+; without them 3assas still traces, and says blocking is off.
- **The observer reports its blind spots.** A per-CPU counter tracks events lost to a full ring buffer or map, and the
  summary says so.

Userspace (Rust, libbpf-rs) resolves `/proc/<pid>/exe` and the container the process runs in (id from
`/proc/<pid>/cgroup` for Docker, Podman, containerd and CRI-O; name from Docker's or rootful Podman's files, else the
short id), labels IPs with their network owner
([iptoasn](https://iptoasn.com), PDDL) and country ([DB-IP Lite](https://db-ip.com), CC BY 4.0) through binary search on
in-memory range tables, and prints a line per event or JSON lines (`--json`). Ctrl-C prints a per-program summary.

## Overhead

`sudo python3 bench/bench.py`: loopback workloads (the worst case, no network latency to hide behind) with the
service stopped and running, alternating every round, median of 7. Apple M1, Fedora Asahi, kernel 7.1.

| Workload | Tracer off | Tracer on | Change |
|---|---|---|---|
| TCP connect + close | 68.9 µs | 68.9 µs | 0 % |
| 512 B UDP datagram | 2.08 µs | 2.34 µs | +12 % (0.26 µs) |
| TCP stream | 78.9 Gbit/s | 81.0 Gbit/s | noise (runs swing 40–82) |

Kernel time per call (`kernel.bpf_stats_enabled`): `on_ingress` 44 ns per received packet, `on_udp4` 110 ns per
send, `on_tcp_state` 839 ns per TCP state change (averaged over the cheap early exits and the connect/close
events that reserve ring buffer space). Only the UDP send path is measurable, and only when nothing else is: a real
network adds milliseconds where 3assas adds a fraction of a microsecond.

## Build from source

Linux ≥ 5.11 with BTF (`/sys/kernel/btf/vmlinux`), clang, bpftool, libelf.

```sh
mkdir -p data
curl -L -o data/ip2asn.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz
curl -L -o data/dbip-country.csv.gz https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).csv.gz
cargo build --release
sudo ./target/release/3assas            # --json, --all (include loopback)
```

## Service mode, agent and web page

```sh
sudo ./install.sh     # builds, installs and starts both services at boot
```

- `3assas.service` (root, capabilities bounded to BPF/PERFMON/NET_ADMIN/PTRACE, `/etc` read-only): `3assas --db /var/lib/3assas/3assas.db` writes
  every event to SQLite (WAL, one transaction per batch, 30-day retention).
- `3assas-agent.service` (your user, read-only on the tracer database): every 30 s it flags a program's first time on
  the network, its first contact with a country, or more than 50 MB sent in an hour. An AI (Gemini) judges each flag
  `normal` / `watch` / `suspicious` from the program's last 24 h; anything not normal goes to Telegram. Evening report
  at 21:00. The first 24 h only learn what is normal.
- Web page on `http://127.0.0.1:4545`: programs with their destinations, alerts with verdicts, the report, live feed.
  Bound to localhost and guarded against DNS rebinding (Host header check).

Optional agent config, in `~/.config/3assas/` (mode 600): `gemini` (API key, free tier is enough; or `GEMINI_API_KEY`),
`telegram` (bot token) and `telegram_chat` (chat id). Without them the agent still flags, and the page still shows
everything; there is just no AI verdict or Telegram message. `ASSAS_LANG` sets the language of verdicts and reports.

Several servers: put a central dashboard's address on the first line of `~/.config/3assas/ship` and this server's key
on the second. Every 30 s the agent POSTs new events to `<address>/v1/events` (`Authorization: Bearer <key>`, body
`{"host": ..., "events": [...]}`, 1000 per request). Its cursor moves only on a 2xx answer: while the dashboard is
down, events wait in the local database and are sent later, none twice. With nothing new, it sends an empty batch:
a heartbeat, so the dashboard can tell a quiet server from a dead one.

## Tests

```sh
cargo test                                          # event and DNS parsing, range lookups, database migration
sudo -E cargo test --release -- --include-ignored   # end to end: exact byte counts, a fake DNS answer names the connection
cd agent && python3 -m unittest test_agent         # alert rules, learning period, Telegram retry
```

## Demo

```sh
python3 docs/demo/gen.py    # the real page on http://127.0.0.1:8056 with a fake day and a moving live feed
```

`docs/demo/record.mjs` films it through a headless Chromium (DevTools protocol) and `docs/demo/gif.sh` makes the GIF.

## Limits

- Outbound only; sockets opened before 3assas started are not seen.
- Blocking applies to new sockets: connections a program already holds stay open until it closes them. A blocked
  program can still get network through another one (a socket passed over a Unix socket, a helper process).
- UDP bytes are sent bytes, sampled every 30 s per flow; the tail of a flow after its last report is not counted.
- Country is a geolocation guess and the network owner is the ASN, not the service (a CDN hides the real site).

License: GPL-2.0 (the kernel program uses GPL-only helpers).
