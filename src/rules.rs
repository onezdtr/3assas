//! Block list: executables denied network sockets by the kernel (`on_socket_create`).
//!
//! The list is a root-owned text file, one absolute path per line. `3assas block` and
//! `3assas unblock` edit it; the running tracer notices the change and syncs the kernel map.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context, Result, bail};

pub const DEFAULT_FILE: &str = "/etc/3assas/blocked";
pub const PATH_LEN: usize = 256;

/// Programs that keep the machine online, or that would blind 3assas itself.
const VITAL: [&str; 9] = [
    "3assas", "NetworkManager", "wpa_supplicant", "iwd", "sshd", "tailscaled", "dhclient", "dhcpcd",
    "connmand",
];

/// Kernel map key: the path, zero-padded like the BPF side's `struct path_key`.
pub fn key(path: &str) -> Option<[u8; PATH_LEN]> {
    let b = path.as_bytes();
    if b.len() >= PATH_LEN || b.contains(&0) {
        return None;
    }
    let mut k = [0u8; PATH_LEN];
    k[..b.len()].copy_from_slice(b);
    Some(k)
}

pub fn read(file: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .map(String::from)
        .collect()
}

/// The path the kernel will report for this executable: symlinks resolved
/// (`/usr/bin/python3` runs as `/usr/bin/python3.14`).
fn resolve(arg: &str) -> Result<String> {
    let p = std::fs::canonicalize(arg).with_context(|| format!("{arg}: no such file"))?;
    if !p.is_file() {
        bail!("{} is not a file", p.display());
    }
    let s = p.to_str().context("path is not UTF-8")?.to_owned();
    if key(&s).is_none() {
        bail!("{s}: paths of {PATH_LEN} bytes or more cannot be blocked");
    }
    Ok(s)
}

fn guard(path: &str) -> Result<()> {
    let name = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
    if VITAL.contains(&name) || path.starts_with("/usr/lib/systemd/") || path.starts_with("/lib/systemd/") {
        bail!("{path} keeps this machine online (or is 3assas itself): refusing to block it");
    }
    Ok(())
}

fn write(file: &Path, list: &BTreeSet<String>) -> Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = file.with_extension("tmp");
    let body: String = list.iter().map(|p| format!("{p}\n")).collect();
    std::fs::write(&tmp, body).with_context(|| format!("write {} (run with sudo)", tmp.display()))?;
    std::fs::rename(&tmp, file)?; // atomic: the tracer never reads half a list
    Ok(())
}

/// `3assas block PATH`, `3assas unblock PATH`, `3assas blocked`.
pub fn command(cmd: &str, arg: Option<&str>, file: &Path) -> Result<()> {
    let mut list = read(file);
    match (cmd, arg) {
        ("blocked", _) => {
            if list.is_empty() {
                println!("nothing blocked");
            }
            list.iter().for_each(|p| println!("{p}"));
            return Ok(());
        }
        ("block", Some(a)) => {
            let p = resolve(a)?;
            guard(&p)?;
            if !list.insert(p.clone()) {
                println!("{p} is already blocked");
                return Ok(());
            }
            write(file, &list)?;
            println!("blocked {p}: new sockets are refused (connections already open stay until the program closes them)");
        }
        ("unblock", Some(a)) => {
            // An exact line, or the resolved path of an existing file.
            let p = if list.contains(a) { a.to_owned() } else { resolve(a)? };
            if !list.remove(&p) {
                bail!("{p} is not blocked");
            }
            write(file, &list)?;
            println!("unblocked {p}");
        }
        _ => bail!("usage: 3assas {cmd} PATH"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_zero_padded_and_bounded() {
        let k = key("/usr/bin/curl").unwrap();
        assert_eq!(&k[..13], b"/usr/bin/curl");
        assert!(k[13..].iter().all(|&b| b == 0));
        assert!(key(&format!("/{}", "a".repeat(255))).is_none());
        assert!(key("/bad\0path").is_none());
    }

    #[test]
    fn refuses_vital_programs() {
        for p in ["/usr/local/bin/3assas", "/usr/sbin/NetworkManager", "/usr/lib/systemd/systemd-resolved", "/usr/sbin/sshd"] {
            assert!(guard(p).is_err(), "{p}");
        }
        assert!(guard("/usr/bin/curl").is_ok());
    }

    #[test]
    fn block_and_unblock_edit_the_file() {
        let dir = std::env::temp_dir().join(format!("3assas-rules-{}", std::process::id()));
        let file = dir.join("blocked");
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let exe = exe.to_str().unwrap();
        command("block", Some(exe), &file).unwrap();
        assert_eq!(read(&file).into_iter().collect::<Vec<_>>(), [exe]);
        command("unblock", Some(exe), &file).unwrap();
        assert!(read(&file).is_empty());
        assert!(command("unblock", Some(exe), &file).is_err());
        assert!(command("block", Some("/no/such/file"), &file).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
