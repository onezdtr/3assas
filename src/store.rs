//! SQLite sink for service mode. The tracer (root) is the only writer; the web page and the agent
//! open the file read-only, and WAL lets them read while we write.

use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, params};

pub struct Row {
    pub t_ms: i64,
    pub kind: &'static str,
    pub proto: &'static str,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub ip: String,
    pub port: u16,
    pub owner: Option<String>,
    pub country: Option<String>,
    pub sent: u64,
    pub recv: u64,
    pub duration_ms: u64,
    pub failed: bool,
}

pub struct Store(Connection);

const KEEP_DAYS: i64 = 30;

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let c = Connection::open(path)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS events(
               t INTEGER NOT NULL, kind TEXT NOT NULL, proto TEXT NOT NULL,
               pid INTEGER NOT NULL, uid INTEGER NOT NULL, comm TEXT NOT NULL, exe TEXT NOT NULL,
               ip TEXT NOT NULL, port INTEGER NOT NULL, owner TEXT, country TEXT,
               sent INTEGER NOT NULL, recv INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
               failed INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS events_t ON events(t);
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);",
        )?;
        Ok(Self(c))
    }

    /// One transaction per batch: a few fsyncs per second instead of one per event.
    pub fn insert(&mut self, rows: &[Row]) -> Result<()> {
        let tx = self.0.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO events VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            )?;
            for r in rows {
                st.execute(params![
                    r.t_ms, r.kind, r.proto, r.pid, r.uid, r.comm, r.exe, r.ip, r.port,
                    r.owner, r.country, r.sent as i64, r.recv as i64, r.duration_ms as i64, r.failed
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Housekeeping: drop old events and publish counters for the page.
    pub fn tick(&self, now_ms: i64, drops: u64) -> Result<()> {
        self.0.execute(
            "DELETE FROM events WHERE t < ?1",
            [now_ms - KEEP_DAYS * 86_400_000],
        )?;
        self.0.execute(
            "INSERT INTO meta VALUES ('drops', ?1), ('heartbeat', ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![drops as i64, now_ms],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(t_ms: i64) -> Row {
        Row {
            t_ms, kind: "connect", proto: "TCP", pid: 1, uid: 0, comm: "curl".into(),
            exe: "/usr/bin/curl".into(), ip: "1.1.1.1".into(), port: 443, owner: None,
            country: Some("US".into()), sent: 0, recv: 0, duration_ms: 0, failed: false,
        }
    }

    #[test]
    fn inserts_and_prunes_old_rows() {
        let mut s = Store::open(Path::new(":memory:")).unwrap();
        let now = 100 * 86_400_000;
        s.insert(&[row(now), row(now - 31 * 86_400_000)]).unwrap();
        s.tick(now, 3).unwrap();
        let n: i64 = s.0.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0)).unwrap();
        let d: i64 = s.0.query_row("SELECT value FROM meta WHERE key='drops'", [], |r| r.get(0)).unwrap();
        assert_eq!((n, d), (1, 3));
    }
}
