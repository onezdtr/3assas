// SPDX-License-Identifier: GPL-2.0
// Kernel side of 3assas: who opens which outbound connection, and how much flows through it.
// Design rule: no per-packet work. TCP is observed only on state changes; byte counts are
// read once from tcp_sock at close. UDP is sampled per flow (first packet, then every 30 s).
// One exception: incoming packets get a header check so DNS answers (UDP from port 53) can be
// copied out; everything else leaves after reading 2 small headers.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define PROTO_TCP 6
#define PROTO_UDP 17
// From include/net/tcp_states.h (anonymous enum, not reliably present in vmlinux.h).
#define ST_SYN_SENT 2
#define ST_CLOSE 7

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define DNS_PORT 53
// EDNS default buffer size (DNS flag day 2020): larger answers are cut, their tail records lost.
#define DNS_MAX 1232

#define UDP_REPORT_NS (30ULL * 1000000000ULL)
#define BLOCK_REPORT_NS 1000000000ULL
#define EPERM 1
#define PATH_LEN 256

enum kind { EV_CONNECT = 1, EV_CLOSE = 2, EV_UDP = 3, EV_BLOCKED = 4 };

// Linux 6.12+ kfuncs for LSM programs. Weak: on older kernels the blocker is not loaded
// (userspace disables it) and the rest of the object must still load.
extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym __weak;
extern void bpf_put_file(struct file *file) __ksym __weak;
extern int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz) __ksym __weak;

// Shared with userspace (src/event.rs). Keep the layout in sync: 80 bytes, no implicit padding.
struct event {
	u64 ts_ns;
	u64 bytes_sent;
	u64 bytes_recv;
	u64 duration_ns;
	u32 tgid;
	u32 uid;
	u16 family;
	u16 dport;
	u8 kind;
	u8 proto;
	u8 old_state;
	u8 _pad;
	u8 daddr[16];
	char comm[16];
};

// A raw DNS answer, parsed in userspace (src/dns.rs). Told apart from struct event by its size.
struct dns_event {
	u32 len;
	u32 _pad;
	u8 data[DNS_MAX];
};

// TCP state changes to CLOSE often run in softirq context, where "current" is a random task.
// So the owner is captured at SYN_SENT (always the connect() caller) and kept per socket.
struct owner {
	u64 start_ns;
	u32 tgid;
	u32 uid;
	char comm[16];
};

struct udp_key {
	u32 tgid;
	u16 family;
	u16 dport;
	u8 daddr[16];
};

struct udp_val {
	u64 last_emit_ns;
	u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u64);
	__type(value, struct owner);
} owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct udp_key);
	__type(value, struct udp_val);
} udp_flows SEC(".maps");

// Executables denied network sockets, by full path (zero-padded). Paths, not inode numbers:
// btrfs subvolumes share one device, so (dev, ino) can name two different files.
struct path_key {
	char p[PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct path_key);
	__type(value, u8);
} blocked SEC(".maps");

// Last report per process, so a program retrying in a loop cannot flood the ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, u64);
} block_reports SEC(".maps");

// Set by userspace while the block list is non-empty: an empty list costs one load per socket.
volatile u32 blocking;

// Events lost because the ring buffer or the owners map was full: the observer must report its blind spots.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	u32 zero = 0;
	u64 *n = bpf_map_lookup_elem(&drops, &zero);
	if (n)
		(*n)++;
}

static __always_inline struct event *reserve(u8 kind, u8 proto)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->proto = proto;
	return e;
}

static __always_inline void sk_dest(const struct sock *sk, struct event *e)
{
	e->family = sk->__sk_common.skc_family;
	e->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	if (e->family == AF_INET)
		bpf_probe_read_kernel(e->daddr, 4, &sk->__sk_common.skc_daddr);
	else
		bpf_probe_read_kernel(e->daddr, 16, &sk->__sk_common.skc_v6_daddr);
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_tcp_state, struct sock *sk, int oldstate, int newstate)
{
	if (sk->sk_protocol != PROTO_TCP)
		return 0;
	u64 key = (u64)sk;

	if (newstate == ST_SYN_SENT) {
		struct owner o = {};
		u64 id = bpf_get_current_pid_tgid();
		o.start_ns = bpf_ktime_get_ns();
		o.tgid = id >> 32;
		o.uid = (u32)bpf_get_current_uid_gid();
		bpf_get_current_comm(o.comm, sizeof(o.comm));
		if (bpf_map_update_elem(&owners, &key, &o, BPF_ANY))
			count_drop();

		struct event *e = reserve(EV_CONNECT, PROTO_TCP);
		if (!e)
			return 0;
		e->tgid = o.tgid;
		e->uid = o.uid;
		__builtin_memcpy(e->comm, o.comm, sizeof(e->comm));
		sk_dest(sk, e);
		bpf_ringbuf_submit(e, 0);
		return 0;
	}

	if (newstate != ST_CLOSE)
		return 0;
	struct owner *o = bpf_map_lookup_elem(&owners, &key);
	if (!o) // passive socket, or opened before we started
		return 0;

	struct event *e = reserve(EV_CLOSE, PROTO_TCP);
	if (e) {
		// Checked downcast: the verifier rejects a plain cast past the end of struct sock.
		struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
		e->tgid = o->tgid;
		e->uid = o->uid;
		__builtin_memcpy(e->comm, o->comm, sizeof(e->comm));
		e->duration_ns = e->ts_ns - o->start_ns;
		if (tp) {
			// Payload only: bytes_acked/bytes_received live in sequence space, where SYN and FIN count as 1 byte.
			e->bytes_sent = tp->bytes_sent - tp->bytes_retrans;
			e->bytes_recv = tp->bytes_received;
			// RCV_SHUTDOWN after a FIN; a local shutdown(SHUT_RD) without FIN would undercount by 1, accepted.
			if ((sk->sk_shutdown & 1) && e->bytes_recv)
				e->bytes_recv--;
		}
		e->old_state = oldstate;
		sk_dest(sk, e);
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&owners, &key);
	return 0;
}

// Destination of a UDP send: explicit address (sendto) wins, else the connected peer.
static __always_inline int udp_send(struct sock *sk, struct msghdr *msg, size_t len, u16 family)
{
	struct udp_key k = {};
	k.family = family;
	void *name = msg->msg_name;
	if (name) {
		if (family == AF_INET) {
			struct sockaddr_in sin;
			bpf_probe_read_kernel(&sin, sizeof(sin), name);
			k.dport = bpf_ntohs(sin.sin_port);
			__builtin_memcpy(k.daddr, &sin.sin_addr, 4);
		} else {
			struct sockaddr_in6 sin6;
			bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
			k.dport = bpf_ntohs(sin6.sin6_port);
			__builtin_memcpy(k.daddr, &sin6.sin6_addr, 16);
		}
	} else {
		k.dport = bpf_ntohs(sk->__sk_common.skc_dport);
		if (family == AF_INET)
			bpf_probe_read_kernel(k.daddr, 4, &sk->__sk_common.skc_daddr);
		else
			bpf_probe_read_kernel(k.daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
	k.tgid = bpf_get_current_pid_tgid() >> 32;

	u64 now = bpf_ktime_get_ns();
	u64 bytes;
	struct udp_val *v = bpf_map_lookup_elem(&udp_flows, &k);
	if (!v) {
		struct udp_val nv = { .last_emit_ns = now, .bytes = 0 };
		bpf_map_update_elem(&udp_flows, &k, &nv, BPF_NOEXIST);
		bytes = len;
	} else {
		__sync_fetch_and_add(&v->bytes, len);
		if (now - v->last_emit_ns < UDP_REPORT_NS)
			return 0;
		// shortcut: two CPUs can both pass this check and report the same window twice; harmless for a monitor, upgrade to a spin lock if counts must be exact
		v->last_emit_ns = now;
		bytes = __sync_lock_test_and_set(&v->bytes, 0);
	}

	struct event *e = reserve(EV_UDP, PROTO_UDP);
	if (!e)
		return 0;
	e->tgid = k.tgid;
	e->uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->family = family;
	e->dport = k.dport;
	__builtin_memcpy(e->daddr, k.daddr, 16);
	e->bytes_sent = bytes;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp4, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, len, AF_INET);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udp6, struct sock *sk, struct msghdr *msg, size_t len)
{
	return udp_send(sk, msg, len, AF_INET6);
}

// Attached to the root cgroup, so it sees what every local socket receives, loopback included
// (the systemd-resolved stub answering programs on 127.0.0.53). Never drops a packet: always returns 1.
SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb)
{
	u32 off;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) || ip.protocol != PROTO_UDP)
			return 1;
		off = ip.ihl * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		// shortcut: a UDP header behind IPv6 extension headers is missed; walk them if DNS over such packets shows up
		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)) || ip6.nexthdr != PROTO_UDP)
			return 1;
		off = sizeof(ip6);
	} else {
		return 1;
	}
	struct udphdr udp;
	if (bpf_skb_load_bytes(skb, off, &udp, sizeof(udp)) || udp.source != bpf_htons(DNS_PORT))
		return 1;
	off += sizeof(udp);
	if (skb->len <= off)
		return 1;
	u32 len = skb->len - off;
	if (len > DNS_MAX)
		len = DNS_MAX;

	struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 1;
	}
	// The verifier needs 1 <= len <= DNS_MAX on the very register passed to the helper:
	// barrier_var stops clang from merging these checks with the ones above.
	barrier_var(len);
	if (len < 1 || len > DNS_MAX || bpf_skb_load_bytes(skb, off, e->data, len)) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}
	e->len = len;
	e->_pad = 0;
	bpf_ringbuf_submit(e, 0);
	return 1;
}

// Deny IPv4/IPv6 socket creation to blocked executables. Once per socket, not per packet, and it
// covers TCP, UDP, QUIC and raw sockets alike. Unix sockets (D-Bus, X11, Wayland) stay allowed.
SEC("lsm/socket_create")
int BPF_PROG(on_socket_create, int family, int type, int protocol, int kern, int ret)
{
	if (ret || kern || !blocking || (family != AF_INET && family != AF_INET6))
		return ret;
	struct file *exe = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!exe)
		return 0;
	struct path_key k = {};
	int n = bpf_path_d_path(&exe->f_path, k.p, sizeof(k.p));
	bpf_put_file(exe);
	if (n <= 0)
		return 0;
	// d_path builds the string at the end of the buffer and the kfunc moves it to the front without
	// clearing the tail, so the leftover copy must be wiped or the key never matches the map's.
	for (int i = 0; i < PATH_LEN; i++)
		if (i >= n)
			k.p[i] = 0;
	if (!bpf_map_lookup_elem(&blocked, &k))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u64 now = bpf_ktime_get_ns();
	u64 *last = bpf_map_lookup_elem(&block_reports, &tgid);
	if (!last || now - *last >= BLOCK_REPORT_NS) {
		bpf_map_update_elem(&block_reports, &tgid, &now, BPF_ANY);
		struct event *e = reserve(EV_BLOCKED, (type & 0xf) == 1 ? PROTO_TCP : PROTO_UDP);
		if (e) {
			e->tgid = tgid;
			e->uid = (u32)bpf_get_current_uid_gid();
			e->family = family;
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
	}
	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
