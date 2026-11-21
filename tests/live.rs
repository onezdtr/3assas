//! End-to-end: kernel hook → ring buffer → JSON line. Needs root, so it is opt-in:
//! `cargo build --release && sudo -E cargo test --release -- --ignored`

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

#[test]
#[ignore = "needs root (loads eBPF)"]
fn sees_our_own_tcp_connection_with_bytes() {
    let mut tracer = Command::new(env!("CARGO_BIN_EXE_3assas"))
        .args(["--json", "--all"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start 3assas");
    let (tx, rx) = mpsc::channel();
    let out = tracer.stdout.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(serde_json::from_str::<serde_json::Value>(&line).unwrap());
        }
    });
    thread::sleep(Duration::from_secs(2)); // attach time

    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let echo = thread::spawn(move || {
        let (mut s, _) = server.accept().unwrap();
        let mut buf = [0u8; 1000];
        s.read_exact(&mut buf).unwrap();
        s.write_all(&[7u8; 5000]).unwrap();
    });
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.write_all(&[1u8; 1000]).unwrap();
    let mut back = Vec::new();
    c.read_to_end(&mut back).unwrap();
    drop(c);
    echo.join().unwrap();

    let me = std::process::id() as u64;
    let seen: Vec<serde_json::Value> = {
        thread::sleep(Duration::from_secs(1)); // let the ring buffer drain
        rx.try_iter().collect()
    };
    let mine = |kind: &str| {
        seen.iter()
            .find(|v| v["event"] == kind && v["pid"] == me && v["port"] == port as u64)
            .cloned()
    };
    let connect = mine("connect").expect("no connect event");
    assert_eq!(connect["ip"], "127.0.0.1");
    let close = mine("close").expect("no close event");
    assert_eq!(close["bytes_sent"], 1000);
    assert_eq!(close["bytes_recv"], 5000);
    assert_eq!(close["failed"], false);

    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(tracer.id() as i32, libc::SIGINT) };
    tracer.wait().unwrap();
}

/// A DNS answer seen in the kernel names the connection that follows it. Plays both sides on
/// loopback: a fake resolver on 127.0.0.1:53 answers `3assas-test.example` with 127.0.0.9,
/// then we connect there.
#[test]
#[ignore = "needs root (loads eBPF, binds port 53)"]
fn names_a_connection_from_the_dns_answer_before_it() {
    use std::net::UdpSocket;

    let mut tracer = Command::new(env!("CARGO_BIN_EXE_3assas"))
        .args(["--json", "--all"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start 3assas");
    let (tx, rx) = mpsc::channel();
    let out = tracer.stdout.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(serde_json::from_str::<serde_json::Value>(&line).unwrap());
        }
    });
    thread::sleep(Duration::from_secs(2));

    let resolver = UdpSocket::bind("127.0.0.1:53").expect("port 53 on 127.0.0.1 is taken");
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(b"query", "127.0.0.1:53").unwrap();
    let (_, from) = resolver.recv_from(&mut [0u8; 64]).unwrap();
    let mut answer = vec![0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    for label in ["3assas-test", "example"] {
        answer.push(label.len() as u8);
        answer.extend(label.as_bytes());
    }
    answer.extend([0, 0, 1, 0, 1]);
    answer.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 9]);
    resolver.send_to(&answer, from).unwrap();
    client.recv_from(&mut [0u8; 512]).unwrap();

    let server = TcpListener::bind("127.0.0.9:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let c = TcpStream::connect(("127.0.0.9", port)).unwrap();
    drop(server.accept().unwrap());
    drop(c);

    thread::sleep(Duration::from_secs(1));
    let me = std::process::id() as u64;
    let connect = rx
        .try_iter()
        .find(|v| v["event"] == "connect" && v["pid"] == me && v["port"] == port as u64)
        .expect("no connect event");
    assert_eq!(connect["domain"], "3assas-test.example");

    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(tracer.id() as i32, libc::SIGINT) };
    tracer.wait().unwrap();
}
