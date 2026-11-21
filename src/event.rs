use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Mirror of `struct event` in src/bpf/tracer.bpf.c.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawEvent {
    pub ts_ns: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub duration_ns: u64,
    pub tgid: u32,
    pub uid: u32,
    pub family: u16,
    pub dport: u16,
    pub kind: u8,
    pub proto: u8,
    pub old_state: u8,
    _pad: u8,
    pub daddr: [u8; 16],
    pub comm: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<RawEvent>() == 80);

pub const EV_CONNECT: u8 = 1;
pub const EV_CLOSE: u8 = 2;
const AF_INET: u16 = 2;
const TCP_SYN_SENT: u8 = 2;

impl RawEvent {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            return None;
        }
        // SAFETY: length checked above; every bit pattern is valid for this plain-old-data struct.
        Some(unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) })
    }

    /// IPv4-mapped IPv6 (dual-stack sockets) is folded back to IPv4.
    pub fn addr(&self) -> IpAddr {
        if self.family == AF_INET {
            let d = self.daddr;
            IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.daddr)).to_canonical()
        }
    }

    pub fn comm(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }

    pub fn proto(&self) -> &'static str {
        if self.proto == 17 { "UDP" } else { "TCP" }
    }

    /// A TCP socket closed straight from SYN_SENT never got an answer.
    pub fn failed(&self) -> bool {
        self.kind == EV_CLOSE && self.old_state == TCP_SYN_SENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(family: u16, daddr: [u8; 16]) -> Vec<u8> {
        let mut b = vec![0u8; 80];
        b[40..42].copy_from_slice(&family.to_ne_bytes());
        b[42..44].copy_from_slice(&443u16.to_ne_bytes());
        b[44] = EV_CONNECT;
        b[48..64].copy_from_slice(&daddr);
        b[64..69].copy_from_slice(b"curl\0");
        b
    }

    #[test]
    fn parses_ipv4_and_mapped_ipv6() {
        let mut d = [0u8; 16];
        d[..4].copy_from_slice(&[1, 1, 1, 1]);
        let e = RawEvent::parse(&raw(2, d)).unwrap();
        assert_eq!(e.addr().to_string(), "1.1.1.1");
        assert_eq!(
            (e.dport, e.kind, e.comm().as_str()),
            (443, EV_CONNECT, "curl")
        );

        let mapped: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        let e = RawEvent::parse(&raw(10, mapped.octets())).unwrap();
        assert_eq!(e.addr().to_string(), "8.8.8.8");
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(RawEvent::parse(&[0u8; 79]).is_none());
    }
}
