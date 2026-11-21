import sqlite3
import unittest

import agent

DAY = 86400 * 1000


def events():
    db = sqlite3.connect(":memory:")
    db.execute("""CREATE TABLE events(t, kind, proto, pid, uid, comm, exe, ip, port, owner, country,
                                      sent, recv, duration_ms, failed)""")
    return db


def add(db, t, exe, country="US", kind="connect", sent=0):
    db.execute("INSERT INTO events VALUES (?, ?, 'TCP', 1, 0, 'x', ?, '1.2.3.4', 443, 'ACME', ?, ?, 0, 0, 0)",
               (t, kind, exe, country, sent))


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
        agent.telegram = lambda text: sent.append(text) and False  # Telegram down
        agent.notify(ag)
        self.assertEqual(ag.execute("SELECT SUM(notified) FROM alerts").fetchone()[0], 0)
        agent.telegram = lambda text: sent.append(text) or True
        agent.notify(ag)
        self.assertIn("b → RU", sent[-1])
        self.assertNotIn("a → CN", sent[-1])
        self.assertEqual(ag.execute("SELECT SUM(notified) FROM alerts").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
