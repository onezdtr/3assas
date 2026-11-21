#!/usr/bin/env python3
"""Overhead of 3assas: kernel time per hook call, and loopback workloads with the tracer off vs on.

Run as root on an idle machine, with 3assas installed as a service (sudo ./install.sh):
    sudo python3 bench/bench.py
It stops and restarts 3assas.service, and turns kernel.bpf_stats_enabled on only while measuring.
Loopback is the worst case: no network latency hides the hooks' cost.
"""
import json
import socket
import statistics
import subprocess
import threading
import time

ROUNDS = 7
CONNECTS = 3000
DATAGRAMS = 50000
BULK = 1 << 30  # bytes
CHUNK = 1 << 16
HOOKS = ("on_tcp_state", "on_udp4", "on_udp6", "on_ingress")


def tcp_connects():
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def accept():
        for _ in range(CONNECTS):
            srv.accept()[0].close()

    t = threading.Thread(target=accept)
    t.start()
    start = time.perf_counter()
    for _ in range(CONNECTS):
        socket.create_connection(("127.0.0.1", port)).close()
    elapsed = time.perf_counter() - start
    t.join()
    srv.close()
    return elapsed / CONNECTS * 1e6, "µs per connect+close"


def udp_sends():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest, payload = rx.getsockname(), b"x" * 512
    start = time.perf_counter()
    for _ in range(DATAGRAMS):
        tx.sendto(payload, dest)
    elapsed = time.perf_counter() - start
    rx.close()
    tx.close()
    return elapsed / DATAGRAMS * 1e6, "µs per 512 B datagram"


def bulk():
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def sink():
        c = srv.accept()[0]
        while c.recv(1 << 20):
            pass
        c.close()

    t = threading.Thread(target=sink)
    t.start()
    c = socket.create_connection(("127.0.0.1", port))
    buf = b"x" * CHUNK
    start = time.perf_counter()
    for _ in range(BULK // CHUNK):
        c.sendall(buf)
    c.close()
    t.join()
    elapsed = time.perf_counter() - start
    srv.close()
    return BULK * 8 / elapsed / 1e9, "Gbit/s TCP stream"


WORKLOADS = (tcp_connects, udp_sends, bulk)


def run_all(samples, units):
    for w in WORKLOADS:
        v, units[w.__name__] = w()
        samples[w.__name__].append(v)


def hook_stats():
    progs = json.loads(subprocess.run(["bpftool", "prog", "show", "--json"], check=True,
                                      capture_output=True, text=True).stdout)
    return {p["name"]: (p.get("run_time_ns", 0), p.get("run_cnt", 0)) for p in progs if p.get("name") in HOOKS}


def service(action):
    subprocess.run(["systemctl", action, "3assas.service"], check=True)
    time.sleep(3)  # attach, or full detach


def main():
    # Off and on alternate every round, so drift (heat, background jobs) hits both sides alike;
    # medians, because loopback throughput swings by 2x between identical runs.
    off = {w.__name__: [] for w in WORKLOADS}
    on = {w.__name__: [] for w in WORKLOADS}
    units, calls = {}, {}
    subprocess.run(["sysctl", "-q", "kernel.bpf_stats_enabled=1"], check=True)
    try:
        for _ in range(ROUNDS):
            service("stop")
            run_all(off, units)
            service("start")
            before = hook_stats()
            run_all(on, units)
            for name, (t, n) in hook_stats().items():
                t0, n0 = before.get(name, (0, 0))
                ct, cn = calls.get(name, (0, 0))
                calls[name] = (ct + t - t0, cn + n - n0)
    finally:
        subprocess.run(["sysctl", "-q", "kernel.bpf_stats_enabled=0"], check=True)
        service("start")

    print(f"{'workload':<14} {'tracer off':>12} {'tracer on':>12} {'change':>8}  unit (median of {ROUNDS})")
    for k, unit in units.items():
        a, b = statistics.median(off[k]), statistics.median(on[k])
        print(f"{k:<14} {a:>12.2f} {b:>12.2f} {(b / a - 1) * 100:>+7.1f}%  {unit}")
    print(f"\n{'hook':<14} {'calls':>10} {'ns/call':>8}")
    for name in HOOKS:
        t, n = calls.get(name, (0, 0))
        if n:
            print(f"{name:<14} {n:>10} {t / n:>8.0f}")


if __name__ == "__main__":
    main()
