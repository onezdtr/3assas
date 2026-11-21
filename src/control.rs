//! Control socket of the service: a local user's agent asks the root tracer to block a program,
//! without root of its own. The kernel tells us who is asking (SO_PEERCRED), so the caller
//! cannot lie about its uid; the policy (what that uid may block) lives in main.rs.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::Duration,
};

use anyhow::Result;

pub const SOCK: &str = "/run/3assas/control.sock";
/// Requests served per loop turn: a client that connects and stalls costs the tracer at most this many timeouts.
const PER_TURN: usize = 4;

pub struct Control(UnixListener);

impl Control {
    pub fn bind(path: &Path) -> Result<Self> {
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)?;
        // Anyone local may ask; the peer's uid decides what is granted.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        l.set_nonblocking(true)?;
        Ok(Self(l))
    }

    /// Answers pending requests: one line in, one line out. `decide(uid, line)` returns the reply.
    pub fn serve(&self, mut decide: impl FnMut(u32, &str) -> String) {
        for _ in 0..PER_TURN {
            let Ok((s, _)) = self.0.accept() else { return };
            let _ = handle(s, &mut decide);
        }
    }
}

fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, a properly sized ucred.
    let rc = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn handle(mut s: UnixStream, decide: &mut impl FnMut(u32, &str) -> String) -> io::Result<()> {
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_millis(300)))?;
    s.set_write_timeout(Some(Duration::from_millis(300)))?;
    let uid = peer_uid(&s)?;
    let mut line = String::new();
    BufReader::new((&s).take(1024)).read_line(&mut line)?;
    let reply = decide(uid, line.trim());
    writeln!(s, "{reply}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_with_the_callers_real_uid() {
        let path = std::env::temp_dir().join(format!("3assas-ctl-{}.sock", std::process::id()));
        let c = Control::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        writeln!(client, "block /usr/bin/x").unwrap();
        let mut seen = None;
        c.serve(|uid, req| {
            seen = Some((uid, req.to_owned()));
            "ok".into()
        });
        let mut reply = String::new();
        BufReader::new(client).read_line(&mut reply).unwrap();
        // SAFETY: getuid has no preconditions.
        assert_eq!(seen, Some((unsafe { libc::getuid() }, "block /usr/bin/x".to_owned())));
        assert_eq!(reply, "ok\n");
        let _ = std::fs::remove_file(path);
    }
}
