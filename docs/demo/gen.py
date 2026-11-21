"""Demo instance for the README GIF: fake but plausible data, nothing from a real machine.

python3 docs/demo/gen.py   -> serves the real page on http://127.0.0.1:8056 with a fake day and a live feed
"""
import os
import random
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

os.environ["ASSAS_PORT"] = "8056"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))
import web  # noqa: E402

DIR = Path(tempfile.mkdtemp(prefix="3assas-demo-"))
EV, AG = DIR / "3assas.db", DIR / "agent.db"
random.seed(7)

# program -> [(owner, country, ip prefix, weight)]
PROGRAMS = {
    "/usr/lib64/firefox/firefox": [("FASTLY", "US", "151.101.", 6), ("GOOGLE", "US", "142.250.", 5),
                                   ("CLOUDFLARENET", "NL", "104.18.", 5), ("AMAZON-02", "IE", "52.48.", 3),
                                   ("MOZILLA-CORP", "US", "34.107.", 2), ("AKAMAI-AS", "FR", "2.16.", 2)],
    "/usr/share/spotify-client/spotify": [("SPOTIFY", "SE", "35.186.", 4), ("GOOGLE", "BE", "34.120.", 2),
                                          ("FASTLY", "DE", "199.232.", 2)],
    "/usr/share/code/code": [("MICROSOFT-CORP", "NL", "13.107.", 4), ("GITHUB", "US", "140.82.", 2)],
    "/usr/bin/slack": [("AMAZON-02", "US", "3.120.", 3), ("CLOUDFLARENET", "US", "162.159.", 2)],
    "/usr/bin/git": [("GITHUB", "US", "140.82.", 1)],
    "/usr/bin/dnf5": [("FASTLY", "FR", "151.101.", 1), ("AKAMAI-AS", "DE", "23.32.", 1)],
    "/usr/sbin/chronyd": [("CLOUDFLARENET", "FR", "162.159.", 1)],
    "/usr/lib/systemd/systemd-resolved": [("local network", None, "192.168.1.", 3)],
    "/home/me/.cache/.x/upd": [("AEZA-AS", "RU", "45.137.", 1)],
}
TRACKERS = ["/usr/lib64/firefox/firefox", "/usr/share/spotify-client/spotify", "/usr/share/code/code", "/usr/bin/slack"]


def event(t, exe, kind=None):
    owner, cc, prefix, _ = random.choices(PROGRAMS[exe], [p[3] for p in PROGRAMS[exe]])[0]
    udp = exe == "/usr/lib/systemd/systemd-resolved" or (kind is None and random.random() < 0.15)
    kind = kind or ("udp" if udp else random.choice(["connect", "close"]))
    big = exe == "/home/me/.cache/.x/upd"
    sent = 0 if kind == "connect" else int(random.lognormvariate(8, 1.4)) * (1350 if big else 1)
    recv = int(random.lognormvariate(10, 1.6)) if kind == "close" else 0
    return (t, kind, "UDP" if kind == "udp" else "TCP", random.randint(900, 9000), 1000, Path(exe).name[:15], exe,
            prefix + f"{random.randint(1, 254)}.{random.randint(1, 254)}" if prefix.count(".") == 2 else prefix + str(random.randint(2, 254)),
            53 if "resolved" in exe else (4444 if big else 443), owner, cc, sent, recv,
            random.randint(40, 9000) if kind == "close" else 0, 0)


def build():
    ev = sqlite3.connect(EV)
    ev.executescript("""PRAGMA journal_mode=WAL;
        CREATE TABLE events(t, kind, proto, pid, uid, comm, exe, ip, port, owner, country, sent, recv, duration_ms, failed);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value);""")
    now = int(time.time() * 1000)
    weights = {"/usr/lib64/firefox/firefox": 40, "/usr/share/spotify-client/spotify": 12, "/usr/share/code/code": 10,
               "/usr/bin/slack": 8, "/usr/bin/git": 2, "/usr/bin/dnf5": 1, "/usr/sbin/chronyd": 2,
               "/usr/lib/systemd/systemd-resolved": 14, "/home/me/.cache/.x/upd": 0.4}
    rows = []
    for exe in random.choices(list(weights), list(weights.values()), k=1500):
        t = now - random.randint(60_000, 86_000_000)
        first = event(t, exe, "udp" if "resolved" in exe or random.random() < 0.15 else "connect")
        rows.append(first)
        if first[1] == "connect":  # every TCP connection closes later, same destination
            close = event(t + random.randint(40, 9000), exe, "close")
            rows.append(close[:7] + first[7:9] + close[9:])
    ev.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", sorted(rows))
    ev.execute("INSERT INTO meta VALUES ('drops', 0), ('heartbeat', ?)", (now,))
    ev.commit()

    ag = sqlite3.connect(AG)
    ag.executescript("""CREATE TABLE alerts(id INTEGER PRIMARY KEY, t, exe, kind, detail, verdict, why, notified);
                        CREATE TABLE reports(t INTEGER PRIMARY KEY, text TEXT);
                        CREATE TABLE meta(key TEXT PRIMARY KEY, value);""")
    ag.execute("INSERT INTO meta VALUES ('started', ?)", (now - 9 * 86_400_000,))
    ag.executemany("INSERT INTO alerts(t, exe, kind, detail, verdict, why, notified) VALUES (?,?,?,?,?,?,1)", [
        (now - 2_400_000, "/home/me/.cache/.x/upd", "new_program",
         "upd used the network for the first time → 45.137.21.9:4444 (AEZA-AS, RU)", "suspicious",
         "A hidden binary in a cache folder talking to a bulletproof host on a non-standard port: not a normal app."),
        (now - 2_300_000, "/home/me/.cache/.x/upd", "big_upload", "upd sent 61.2 MB in the last hour", "suspicious",
         "Large upload from the same unknown binary: possible data exfiltration."),
        (now - 9_000_000, "/usr/share/code/code", "new_country", "code contacted NL for the first time → 13.107.5.88:443 (MICROSOFT-CORP, NL)",
         "normal", "VS Code reaching Microsoft's own network for extensions and telemetry."),
        (now - 21_000_000, "/usr/share/spotify-client/spotify", "new_country",
         "spotify contacted BE for the first time → 34.120.4.77:443 (GOOGLE, BE)", "watch",
         "Spotify runs on Google Cloud, plausible, but a new region for this app."),
        (now - 40_000_000, "/usr/lib64/firefox/firefox", "new_country",
         "firefox contacted IE for the first time → 52.48.10.3:443 (AMAZON-02, IE)", "normal",
         "A browser reaching an Amazon-hosted site in a new region is routine."),
    ])
    ag.execute("INSERT INTO reports VALUES (?, ?)", (now - 3_600_000, (
        "Firefox did most of the talking today: CDNs (Fastly, Cloudflare), Google and Mozilla, nothing unusual.\n"
        "Spotify streamed from its own servers in Sweden and from Google Cloud in Belgium.\n"
        "VS Code checked Microsoft and GitHub for updates.\n\n"
        "One thing stands out: upd, a hidden program in ~/.cache/.x that did not exist yesterday, connected to a "
        "Russian host on port 4444 and sent 61 MB. Find out what installed it and remove it.")))
    ag.commit()


def live():
    """New events every few hundred ms so the page moves while it is filmed."""
    db = sqlite3.connect(EV)
    while True:
        now = int(time.time() * 1000)
        exe = random.choice(TRACKERS + ["/usr/lib/systemd/systemd-resolved"])
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", event(now, exe))
        db.execute("UPDATE meta SET value = ? WHERE key = 'heartbeat'", (now,))
        db.commit()
        time.sleep(random.uniform(0.25, 0.7))


if __name__ == "__main__":
    build()
    threading.Thread(target=live, daemon=True).start()
    print(f"demo on http://127.0.0.1:{web.PORT} ({DIR})", flush=True)
    web.serve(EV, AG)
