import sqlite3
import unittest

import agent

DAY = 86400 * 1000


def events():
    db = sqlite3.connect(":memory:")
    db.execute("""CREATE TABLE events(t, kind, proto, pid, uid, comm, exe, ip, port, owner, country,
                                      sent, recv, duration_ms, failed, domain, container)""")
    return db


def add(db, t, exe, country="US", kind="connect", sent=0):
    db.execute("INSERT INTO events VALUES (?, ?, 'TCP', 1, 0, 'x', ?, '1.2.3.4', 443, 'ACME', ?, ?, 0, 0, 0, 'acme.example', NULL)",
               (t, kind, exe, country, sent))


class Ship(unittest.TestCase):
    def test_sends_in_order_and_resumes_after_a_failure(self):
        ev, ag = events(), agent.open_agent(":memory:")
        for t in range(2500):
            add(ev, t, "/usr/bin/curl")
        got, calls = [], [0]

        def post(body):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError("dashboard down")
            got.extend(e["t"] for e in body["events"])

        with self.assertRaises(OSError):
            agent.ship(ev, ag, post)
        self.assertEqual(got, list(range(1000)))  # 1st batch acknowledged, 2nd failed
        self.assertEqual(agent.ship(ev, ag, post), 1500)  # retry: nothing lost, nothing twice
        self.assertEqual(got, list(range(2500)))
        n = calls[0]
        self.assertEqual(agent.ship(ev, ag, post), 0)  # nothing new: one empty post, the heartbeat
        self.assertEqual((calls[0], got[-1]), (n + 1, 2499))


class Ingest(unittest.TestCase):
    def setUp(self):
        self.ev, self.ag = events(), agent.open_agent(":memory:")

    def kinds(self):
        return [r[0] for r in self.ag.execute("SELECT kind FROM alerts ORDER BY id")]

    def test_learning_day_is_silent_then_new_things_alert_once(self):
        add(self.ev, 0, "/usr/bin/curl")
        self.assertEqual(agent.ingest(self.ev, self.ag, 0), [])  # day 1: learn

        t = DAY + 1
        add(self.ev, t, "/usr/bin/curl")  # known program, known country
        add(self.ev, t, "/usr/bin/curl", country="CN")  # known program, new country
        add(self.ev, t, "/tmp/x", country="RU")  # new program: one alert, not a country one too
        add(self.ev, t, "/tmp/x", country="RU", kind="close")
        agent.ingest(self.ev, self.ag, t)
        self.assertEqual(self.kinds(), ["new_country", "new_program"])

        add(self.ev, t + 1, "/usr/bin/curl", country="CN")  # already seen: nothing
        add(self.ev, t + 1, "/tmp/blocked", country=None, kind="blocked")  # refused by the user's block list: nothing
        agent.ingest(self.ev, self.ag, t + 1)
        self.assertEqual(len(self.kinds()), 2)

    def test_big_upload_alerts_even_while_learning_but_once_per_hour(self):
        add(self.ev, 0, "/usr/bin/rclone", kind="close", sent=agent.BIG_UPLOAD)
        agent.ingest(self.ev, self.ag, 1000)
        agent.ingest(self.ev, self.ag, 2000)
        self.assertEqual(self.kinds(), ["big_upload"])

    def test_cursor_resets_when_tracer_db_is_recreated(self):
        agent.set_meta(self.ag, "cursor", 999)
        add(self.ev, 0, "/usr/bin/curl")
        agent.ingest(self.ev, self.ag, 0)
        self.assertEqual(agent.meta(self.ag, "cursor"), 1)


class Notify(unittest.TestCase):
    def test_normal_verdicts_stay_quiet_and_failed_send_retries(self):
        ag = agent.open_agent(":memory:")
        agent.alert(ag, 0, "/a", "new_country", "a → CN")
        agent.alert(ag, 0, "/b", "new_program", "b → RU")
        ag.execute("UPDATE alerts SET verdict = 'normal' WHERE exe = '/a'")
        sent = []
        agent.telegram = lambda text, buttons=None: sent.append(text) and False  # Telegram down
        agent.notify(ag)
        self.assertEqual(ag.execute("SELECT SUM(notified) FROM alerts").fetchone()[0], 0)
        agent.telegram = lambda text, buttons=None: sent.append(text) or True
        agent.notify(ag)
        self.assertIn("b → RU", sent[-1])
        self.assertNotIn("a → CN", sent[-1])
        self.assertEqual(ag.execute("SELECT SUM(notified) FROM alerts").fetchone()[0], 2)


class Buttons(unittest.TestCase):
    def test_flagged_programs_get_one_block_button_each(self):
        ag = agent.open_agent(":memory:")
        for exe, verdict in (("/tmp/x", "suspicious"), ("/tmp/x", "watch"), ("/usr/bin/ok", "normal"), ("/opt/y", "watch")):
            i = agent.alert(ag, 0, exe, "new_program", exe)
            ag.execute("UPDATE alerts SET verdict = ? WHERE id = ?", (verdict, i))
        got = []
        agent.telegram = lambda text, buttons=None: got.append(buttons) or True
        agent.notify(ag)
        self.assertEqual([t for t, _ in got[0]], ["⊘ Block x", "⊘ Block y"])

    def test_only_the_owner_can_press(self):
        ag = agent.open_agent(":memory:")
        i = agent.alert(ag, 0, "/tmp/x", "new_program", "x")
        asked = []
        agent.block = lambda exe: asked.append(exe) or "ok blocked " + exe
        tap = lambda who, data: {"update_id": 1, "callback_query": {"id": "q", "from": {"id": who}, "data": data}}
        self.assertIsNone(agent.on_button(ag, tap(666, f"block:{i}"), 42))  # a stranger
        self.assertIsNone(agent.on_button(ag, tap(42, "block:999"), 42))  # unknown alert
        self.assertIsNone(agent.on_button(ag, {"update_id": 2, "message": {"text": "/start"}}, 42))
        self.assertEqual(agent.on_button(ag, tap(42, f"block:{i}"), 42), "⊘ x blocked")
        self.assertEqual(asked, ["/tmp/x"])


class ControlSocket(unittest.TestCase):
    def test_block_sends_one_line_and_reads_the_answer(self):
        import importlib, socket, tempfile, threading
        path = tempfile.mktemp(suffix=".sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        got = []

        def answer():
            c, _ = srv.accept()
            got.append(c.makefile().readline())
            c.sendall(b"ok blocked /tmp/x\n")
            c.close()

        threading.Thread(target=answer).start()
        real = importlib.reload(agent)  # undo the monkeypatching of other tests
        real.CONTROL = path
        self.assertEqual(real.block("/tmp/x"), "ok blocked /tmp/x")
        self.assertEqual(got, ["block /tmp/x\n"])
        real.CONTROL = path + ".missing"
        self.assertTrue(real.block("/tmp/x").startswith("error: tracer unreachable"))
        srv.close()


if __name__ == "__main__":
    unittest.main()
