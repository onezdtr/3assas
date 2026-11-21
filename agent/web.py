"""Web page of 3assas: read-only view of the tracer database and the agent's alerts.

Listens on 127.0.0.1 only: connection history is private. Reach it from elsewhere through an SSH tunnel.
"""
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(os.environ.get("ASSAS_PORT", "4545"))
PAGE = Path(__file__).with_name("page.html")


def rows(db, sql, args, keys):
    return [dict(zip(keys, r)) for r in db.execute(sql, args)]


def state(ev_path, ag_path, now):
    day = now - 86400 * 1000
    ev = sqlite3.connect(f"file:{ev_path}?mode=ro", uri=True, timeout=5)
    try:
        meta = dict(ev.execute("SELECT key, value FROM meta"))
        total = rows(ev, """SELECT COALESCE(SUM(kind IN ('connect', 'udp')), 0), COUNT(DISTINCT exe), COALESCE(SUM(sent), 0),
                                   COALESCE(SUM(recv), 0), COUNT(DISTINCT country) FROM events WHERE t >= ?""",
                     (day,), ("connections", "programs", "sent", "recv", "countries"))[0]
        programs = rows(ev, """SELECT exe, SUM(kind IN ('connect', 'udp')), COUNT(DISTINCT NULLIF(ip, '')), SUM(sent), SUM(recv),
                                      GROUP_CONCAT(DISTINCT country), MAX(t)
                               FROM events WHERE t >= ? GROUP BY exe ORDER BY SUM(sent) + SUM(recv) DESC LIMIT 60""",
                        (day,), ("exe", "connections", "dests", "sent", "recv", "countries", "last"))
        feed = rows(ev, """SELECT t, kind, proto, exe, ip, port, domain, owner, country, sent, recv, duration_ms, failed
                           FROM events ORDER BY rowid DESC LIMIT 80""", (),
                    ("t", "kind", "proto", "exe", "ip", "port", "domain", "owner", "country", "sent", "recv", "duration_ms",
                     "failed"))
    finally:
        ev.close()
    alerts, report, started = [], None, None
    if Path(ag_path).exists():
        ag = sqlite3.connect(f"file:{ag_path}?mode=ro", uri=True, timeout=5)
        try:
            alerts = rows(ag, "SELECT t, exe, kind, detail, verdict, why FROM alerts ORDER BY id DESC LIMIT 40", (),
                          ("t", "exe", "kind", "detail", "verdict", "why"))
            report = ag.execute("SELECT t, text FROM reports ORDER BY t DESC LIMIT 1").fetchone()
            started = (ag.execute("SELECT value FROM meta WHERE key = 'started'").fetchone() or [None])[0]
        finally:
            ag.close()
    return {"now": now, "heartbeat": meta.get("heartbeat"), "drops": meta.get("drops", 0), "total": total,
            "programs": programs, "feed": feed, "alerts": alerts, "learning_until": started and started + 86400 * 1000,
            "report": report and {"t": report[0], "text": report[1]}}


def program(ev_path, exe, now):
    ev = sqlite3.connect(f"file:{ev_path}?mode=ro", uri=True, timeout=5)
    try:
        return rows(ev, """SELECT domain, COALESCE(owner, '?'), country, COUNT(DISTINCT NULLIF(ip, '')), SUM(kind IN ('connect', 'udp')),
                                  SUM(sent), SUM(recv), MAX(t)
                           FROM events WHERE exe = ? AND t >= ? GROUP BY 1, 2, 3 ORDER BY SUM(sent) + SUM(recv) DESC LIMIT 40""",
                    (exe, now - 86400 * 1000), ("domain", "owner", "country", "ips", "connections", "sent", "recv", "last"))
    finally:
        ev.close()


def serve(ev_path, ag_path):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, body, kind):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # DNS rebinding guard: a hostile site resolving to 127.0.0.1 still sends its own Host header.
            if self.headers.get("Host") not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
                return self.reply(403, b"forbidden", "text/plain")
            url = urlparse(self.path)
            now = int(time.time() * 1000)
            try:
                if url.path == "/":
                    return self.reply(200, PAGE.read_bytes(), "text/html; charset=utf-8")
                if url.path == "/api/state":
                    data = state(ev_path, ag_path, now)
                elif url.path == "/api/program":
                    data = program(ev_path, parse_qs(url.query).get("exe", [""])[0], now)
                else:
                    return self.reply(404, b"not found", "text/plain")
            except sqlite3.Error as e:
                return self.reply(503, json.dumps({"error": str(e)}).encode(), "application/json")
            self.reply(200, json.dumps(data).encode(), "application/json")

        def log_message(self, *_):
            pass

    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
