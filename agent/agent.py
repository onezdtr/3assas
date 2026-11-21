"""3assas agent: runs 24/7 next to the tracer.

Config (optional): ~/.config/3assas/gemini (API key), telegram + telegram_chat (bot token, chat id).
The bot must be dedicated to 3assas: the agent reads its updates for the Block buttons.

Every 30 s it reads the new events (read-only), flags what is new for each program (first time on the network,
first contact with a country, large upload), asks an AI to judge each flag, and sends the ones that matter to
Telegram. At 21:00 it writes the evening report. It also serves the web page (web.py).

Usage: python3 agent.py            -> run forever (systemd: 3assas-agent.service)
       python3 agent.py --report   -> print tonight's report now and exit
"""
import json
import os
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import web

DB = Path(os.environ.get("ASSAS_DB", "/var/lib/3assas/3assas.db"))
AGENT_DB = Path(os.environ.get("ASSAS_AGENT_DB", Path.home() / ".local/share/3assas/agent.db"))
CONF = Path.home() / ".config/3assas"
MODEL = os.environ.get("ASSAS_MODEL", "gemini-3.1-flash-lite")
LANG = os.environ.get("ASSAS_LANG", "French")
LEARN_MS = 24 * 3600 * 1000  # first day: learn what is normal, alert on nothing but large uploads
BIG_UPLOAD = 50_000_000  # bytes sent by one program within an hour
REPORT_HOUR = 21
CYCLE_S = 30
CONTROL = os.environ.get("ASSAS_CONTROL", "/run/3assas/control.sock")

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen(exe TEXT, what TEXT, value TEXT, first_t INTEGER, PRIMARY KEY (exe, what, value));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, t INTEGER, exe TEXT, kind TEXT, detail TEXT,
                                  verdict TEXT, why TEXT, notified INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS reports(t INTEGER PRIMARY KEY, text TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value);
"""

JUDGE = f"""You watch the network activity of one Linux laptop, program by program, captured in the kernel (eBPF).
You get alerts (a program's first time on the network, its first contact with a country, a large upload) and, for
each program involved, where it connected in the last 24 hours (domain = the name it looked up, when known;
network owner = ASN; country).
For every alert decide a verdict:
- "normal": expected for that kind of program (a browser reaching a CDN in a new country, a package manager
  reaching its mirrors, a system service reaching its vendor);
- "watch": unusual but plausible;
- "suspicious": no good reason for this program to talk to this place, a binary in /tmp or a home folder
  phoning out, a large upload to an unexpected owner.
Give a one-sentence reason in plain {LANG}. Use only the data given; when unsure, say "watch"."""
JUDGE_SCHEMA = {"type": "ARRAY", "items": {"type": "OBJECT", "required": ["id", "verdict", "why"], "properties": {
    "id": {"type": "INTEGER"}, "verdict": {"type": "STRING", "enum": ["normal", "watch", "suspicious"]},
    "why": {"type": "STRING"}}}}

REPORT = f"""You write the evening report of a Linux laptop's network activity, captured per program in the kernel.
You get, for the last 24 hours, each program with its connections, bytes sent/received, main network owners and
countries and the domain names it looked up, plus the alerts of the day with their verdicts. Write in plain {LANG}, for Telegram, no markdown,
1500 characters at most: one line per notable program (what it talked to, in words a non-expert understands),
then anything surprising. Skip programs with nothing to say. Use only the data given."""


def now_ms():
    return int(time.time() * 1000)


def human(b):
    for unit in ("B", "kB", "MB", "GB"):
        if b < 1000 or unit == "GB":
            return f"{b:.0f} {unit}" if unit == "B" else f"{b:.1f} {unit}"
        b /= 1000


def name(exe):
    return exe.rsplit("/", 1)[-1]


def open_agent(path=AGENT_DB):
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=5)
    db.executescript(SCHEMA)
    return db


def open_events(path=DB):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)


def meta(db, key, default=None):
    row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(db, key, value):
    db.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def first(ag, exe, what, value, t):
    """True the first time this (program, kind, value) is seen."""
    return ag.execute("INSERT OR IGNORE INTO seen VALUES (?, ?, ?, ?)", (exe, what, value, t)).rowcount == 1


def alert(ag, t, exe, kind, detail):
    return ag.execute("INSERT INTO alerts(t, exe, kind, detail) VALUES (?, ?, ?, ?)", (t, exe, kind, detail)).lastrowid


def ingest(ev, ag, now):
    """Read events past the cursor, record what each program does, return the ids of new alerts."""
    started = meta(ag, "started")
    if started is None:
        started = now
        set_meta(ag, "started", now)
    learned = now - started >= LEARN_MS
    cursor = meta(ag, "cursor", 0)
    if cursor > (ev.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0]):
        cursor = 0  # the tracer database was recreated
    created = []
    while True:
        rows = ev.execute("""SELECT rowid, t, kind, exe, ip, port, owner, country, domain FROM events
                             WHERE rowid > ? ORDER BY rowid LIMIT 5000""", (cursor,)).fetchall()
        for rowid, t, kind, exe, ip, port, owner, cc, domain in rows:
            cursor = rowid
            if kind in ("close", "blocked"):  # blocked: refused before reaching anything
                continue
            labels = ", ".join(x for x in (owner, cc) if x)
            where = (f"{domain} " if domain else "") + f"{ip}:{port}" + (f" ({labels})" if labels else "")
            new_program = first(ag, exe, "program", "", t)
            if new_program and learned:
                created.append(alert(ag, t, exe, "new_program", f"{name(exe)} used the network for the first time → {where}"))
            if cc and first(ag, exe, "country", cc, t) and learned and not new_program:
                created.append(alert(ag, t, exe, "new_country", f"{name(exe)} contacted {cc} for the first time → {where}"))
        if len(rows) < 5000:
            break
    set_meta(ag, "cursor", cursor)

    hour_ago = now - 3600 * 1000
    for exe, sent in ev.execute("SELECT exe, SUM(sent) FROM events WHERE t >= ? GROUP BY exe HAVING SUM(sent) >= ?",
                                (hour_ago, BIG_UPLOAD)).fetchall():
        if not ag.execute("SELECT 1 FROM alerts WHERE exe = ? AND kind = 'big_upload' AND t >= ?", (exe, hour_ago)).fetchone():
            created.append(alert(ag, now, exe, "big_upload", f"{name(exe)} sent {human(sent)} in the last hour"))
    ag.commit()
    return created


def profile(ev, exes, since):
    """Where each program connected since `since`: the context the AI judges with."""
    out = {}
    for exe in exes:
        dests = ev.execute("""SELECT domain, COALESCE(owner, ip), country, COUNT(*), SUM(sent), SUM(recv) FROM events
                              WHERE exe = ? AND t >= ? GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 15""", (exe, since)).fetchall()
        out[exe] = [dict(zip(("domain", "owner", "country", "events", "sent", "recv"), d)) for d in dests]
    return out


def key():
    """GEMINI_API_KEY, else ~/.config/3assas/gemini (keeps the key out of the unit file and shell history)."""
    f = CONF / "gemini"
    return os.environ.get("GEMINI_API_KEY") or (f.read_text().strip() if f.exists() else "")


def ask(system, data, schema=None):
    body = {"systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": json.dumps(data, ensure_ascii=False)}]}]}
    if schema:
        body["generationConfig"] = {"responseMimeType": "application/json", "responseSchema": schema}
    req = urllib.request.Request(f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent",
                                 json.dumps(body).encode(), {"Content-Type": "application/json", "x-goog-api-key": key()})
    for attempt in range(3):
        try:
            reply = json.load(urllib.request.urlopen(req, timeout=120))
            break
        except urllib.error.HTTPError as e:  # 429/503: the free tier is busy, back off and retry
            if e.code not in (429, 503) or attempt == 2:
                raise
            time.sleep(10 * (attempt + 1))
    return "".join(p.get("text", "") for p in reply["candidates"][0]["content"]["parts"])


def judge(ev, ag, ids, now):
    """AI verdict on each alert. On failure the alerts stay unjudged and go out as they are."""
    for i in range(0, len(ids), 40):
        chunk = ag.execute(f"SELECT id, exe, kind, detail FROM alerts WHERE id IN ({','.join('?' * len(ids[i:i + 40]))})",
                           ids[i:i + 40]).fetchall()
        data = {"alerts": [dict(zip(("id", "program", "kind", "detail"), a)) for a in chunk],
                "programs": profile(ev, {a[1] for a in chunk}, now - 86400 * 1000)}
        for v in json.loads(ask(JUDGE, data, JUDGE_SCHEMA)):
            if v.get("verdict") in ("normal", "watch", "suspicious"):
                ag.execute("UPDATE alerts SET verdict = ?, why = ? WHERE id = ?", (v["verdict"], v["why"][:300], v["id"]))
        ag.commit()


def bot():
    """(token, chat id) from ~/.config/3assas, or None when Telegram is not configured."""
    tok, chat = CONF / "telegram", CONF / "telegram_chat"
    if not (tok.exists() and chat.exists()):
        return None
    return tok.read_text().strip(), int(chat.read_text().strip())


def api(method, payload, timeout=15):
    token, _ = bot()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", json.dumps(payload).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["result"]


def telegram(text, buttons=None):
    """Sends to the configured chat, with optional inline buttons [(label, data)]. No bot, no message. Never raises."""
    if not bot():
        return False
    msg = {"chat_id": bot()[1], "text": text[:4000], "disable_web_page_preview": True}
    if buttons:
        msg["reply_markup"] = {"inline_keyboard": [[{"text": t, "callback_data": d}] for t, d in buttons]}
    try:
        api("sendMessage", msg)
        return True
    except (OSError, ValueError, KeyError) as e:
        print("telegram not sent:", e, flush=True)
        return False


def block(exe):
    """Asks the root tracer to block `exe` over its control socket. The tracer checks our uid itself."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(CONTROL)
            s.sendall(f"block {exe}\n".encode())
            return s.makefile().readline().strip() or "error: no answer"
    except OSError as e:
        return f"error: tracer unreachable ({e})"


def on_button(ag, update, chat):
    """Handles one Telegram update; returns the reply to show, or None to ignore it."""
    q = update.get("callback_query")
    if not q or q.get("from", {}).get("id") != chat:  # only the owner's taps count
        return None
    kind, _, alert = q.get("data", "").partition(":")
    row = ag.execute("SELECT exe FROM alerts WHERE id = ?", (alert,)).fetchone() if kind == "block" else None
    if not row:
        return None
    answer = block(row[0])
    return f"⊘ {name(row[0])} blocked" if answer.startswith("ok") else f"Not blocked: {answer.removeprefix('error: ')}"


def listen():
    """Long-polls the bot for Block taps. Stops if another program reads the same bot (HTTP 409)."""
    ag = open_agent()
    offset = 0
    while True:
        try:
            updates = api("getUpdates", {"offset": offset, "timeout": 50}, timeout=60)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("Block buttons off: another program reads this bot, give 3assas its own", flush=True)
                return
            time.sleep(10)
            continue
        except (OSError, ValueError, KeyError):
            time.sleep(10)
            continue
        for u in updates:
            offset = u["update_id"] + 1
            reply = on_button(ag, u, bot()[1])
            if reply:
                print("button:", reply, flush=True)
                try:
                    api("answerCallbackQuery", {"callback_query_id": u["callback_query"]["id"], "text": reply[:190]})
                except (OSError, ValueError, KeyError):
                    pass
                telegram(reply)


ICON = {"suspicious": "🔴", "watch": "🟠", None: "⚪"}


def notify(ag):
    """One Telegram message per cycle with everything not judged normal, and a Block button per program flagged."""
    rows = ag.execute("SELECT id, verdict, detail, why, exe FROM alerts WHERE notified = 0 ORDER BY id").fetchall()
    worth = [r for r in rows if r[1] != "normal"]
    if worth:
        lines = [f"{ICON.get(v, '⚪')} {d}" + (f"\n   {w}" if w else "") for _, v, d, w, _ in worth[:10]]
        if len(worth) > 10:
            lines.append(f"… and {len(worth) - 10} more on the page")
        buttons = {}
        for i, v, _, _, exe in worth:
            if v in ("suspicious", "watch") and exe not in buttons and len(buttons) < 4:
                buttons[exe] = (f"⊘ Block {name(exe)}", f"block:{i}")
        if not telegram("3assas\n\n" + "\n".join(lines), list(buttons.values())):
            return  # retry next cycle
    ag.executemany("UPDATE alerts SET notified = 1 WHERE id = ?", [(r[0],) for r in rows])
    ag.commit()


def report(ev, ag, now):
    since = now - 86400 * 1000
    progs = ev.execute("""SELECT exe, SUM(kind IN ('connect', 'udp')), SUM(sent), SUM(recv) FROM events WHERE t >= ?
                          GROUP BY exe ORDER BY SUM(sent) + SUM(recv) DESC LIMIT 25""", (since,)).fetchall()
    places = profile(ev, [p[0] for p in progs], since)
    data = {"programs": [{"program": e, "connections": c, "sent": s, "received": r, "main_destinations": places[e][:6]}
                         for e, c, s, r in progs],
            "alerts": [dict(zip(("detail", "verdict", "why"), a)) for a in
                       ag.execute("SELECT detail, verdict, why FROM alerts WHERE t >= ?", (since,))]}
    try:
        text = ask(REPORT, data)
    except (OSError, ValueError, KeyError, IndexError) as e:
        print("report without AI:", e, flush=True)
        text = "\n".join(f"{name(e)}: {c} connections, ↑{human(s)} ↓{human(r)}" for e, c, s, r in progs[:12])
    ag.execute("INSERT OR REPLACE INTO reports VALUES (?, ?)", (now, text))
    ag.commit()
    return text


def cycle(ag, now):
    if not DB.exists():
        return
    ev = open_events()
    try:
        ids = ingest(ev, ag, now)
        if ids:
            try:
                judge(ev, ag, ids, now)
            except (OSError, ValueError, KeyError, IndexError) as e:
                print("AI judge failed, alerts sent unjudged:", e, flush=True)
        notify(ag)
        today = time.strftime("%Y-%m-%d")
        if time.localtime().tm_hour >= REPORT_HOUR and meta(ag, "report_day") != today:
            set_meta(ag, "report_day", today)
            telegram("3assas · evening report\n\n" + report(ev, ag, now))
    finally:
        ev.close()


def main():
    ag = open_agent()
    if "--report" in sys.argv:
        print(report(open_events(), ag, now_ms()))
        return
    threading.Thread(target=web.serve, args=(DB, AGENT_DB), daemon=True).start()
    if bot():
        threading.Thread(target=listen, daemon=True).start()
    print(f"3assas agent: watching {DB}, page on http://{web.HOST}:{web.PORT}", flush=True)
    while True:
        try:
            cycle(ag, now_ms())
        except sqlite3.Error as e:  # tracer restarting, file being rotated: try again next cycle
            print("database not readable:", e, flush=True)
        time.sleep(CYCLE_S)


if __name__ == "__main__":
    main()
