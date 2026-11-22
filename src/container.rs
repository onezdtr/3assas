//! Which container a process runs in: the id from its cgroup path, the name from the engine's files.

use std::path::Path;

/// Container id (64 hex) in a /proc/PID/cgroup file, for Docker, Podman, containerd and CRI-O, cgroup v1 or v2.
pub fn id(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/'))
        .filter_map(|seg| {
            let seg = seg.strip_suffix(".scope").unwrap_or(seg);
            let id = ["docker-", "libpod-", "cri-containerd-", "crio-"]
                .iter()
                .find_map(|p| seg.strip_prefix(p))
                .unwrap_or(seg);
            (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).then(|| id.to_owned())
        })
        .last()
}

/// Human name of a container, or its short id when no engine file names it.
/// shortcut: Docker and rootful Podman only (rootless Podman lives under /home, Kubernetes in containerd); read
/// the CRI socket when Kubernetes users ask.
pub fn name(id: &str, root: &Path) -> String {
    let docker = std::fs::read(root.join(format!("var/lib/docker/containers/{id}/config.v2.json")))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["Name"].as_str().map(|n| n.trim_start_matches('/').to_owned()));
    // `podman run --rm` containers are listed in volatile-containers.json, the others in containers.json.
    let podman = || {
        ["containers.json", "volatile-containers.json"].iter().find_map(|f| {
            let b = std::fs::read(root.join("var/lib/containers/storage/overlay-containers").join(f)).ok()?;
            let v: serde_json::Value = serde_json::from_slice(&b).ok()?;
            v.as_array()?.iter().find(|c| c["id"] == id)?["names"][0].as_str().map(String::from)
        })
    };
    docker
        .or_else(podman)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| id[..12].to_owned())
}

/// Container label of a running process, None on the host.
pub fn of(pid: u32) -> Option<String> {
    let id = id(&std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?)?;
    Some(name(&id, Path::new("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";

    #[test]
    fn finds_the_id_for_each_engine_and_nothing_on_the_host() {
        for line in [
            format!("0::/system.slice/docker-{ID}.scope"),
            format!("0::/machine.slice/libpod-{ID}.scope/container"),
            format!("0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{ID}.scope"),
            format!("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b.slice/cri-containerd-{ID}.scope"),
            format!("12:pids:/docker/{ID}\n11:memory:/docker/{ID}"),
            format!("0::/kubepods/besteffort/pod1a2b/{ID}"),
        ] {
            assert_eq!(id(&line).as_deref(), Some(ID), "{line}");
        }
        for host in [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kitty-2732-0.scope",
            "0::/system.slice/sshd.service",
            &format!("0::/machine.slice/libpod-conmon-{ID}.scope"), // podman's monitor, not the container
            &format!("0::/system.slice/docker-{}.scope", ID.to_uppercase()),
        ] {
            assert_eq!(id(host), None, "{host}");
        }
    }

    #[test]
    fn names_from_docker_then_podman_else_short_id() {
        let root = std::env::temp_dir().join(format!("3assas-ctr-{}", std::process::id()));
        assert_eq!(name(ID, &root), &ID[..12]);
        let d = root.join(format!("var/lib/docker/containers/{ID}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("config.v2.json"), r#"{"Name":"/api","ID":"x"}"#).unwrap();
        assert_eq!(name(ID, &root), "api");
        std::fs::remove_dir_all(root.join("var/lib/docker")).unwrap();
        let p = root.join("var/lib/containers/storage/overlay-containers");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("containers.json"), r#"[{"id":"x","names":["no"]}]"#).unwrap();
        std::fs::write(p.join("volatile-containers.json"), format!(r#"[{{"id":"{ID}","names":["worker"]}}]"#)).unwrap();
        assert_eq!(name(ID, &root), "worker");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
