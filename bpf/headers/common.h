#pragma once

// Kernel sparse annotations — vmlinux.h may define __user as an address-space
// attribute that clang's BPF target rejects. Force it to empty unconditionally.
#undef __user
#define __user

// Socket family constants — defined as #defines in <linux/socket.h>,
// not captured by BTF. Force-define unconditionally.
#undef AF_INET
#undef AF_INET6
#define AF_INET 2
#define AF_INET6 10

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define MAX_SSL_BUF 4096
#define IPV6_LEN 16

// Event types must match events.Type in Go
#define EVENT_FILE_OPEN 0
#define EVENT_NET_CONNECT 1
#define EVENT_EXEC 2
#define EVENT_SSL_DATA 3

// SSL direction constants
#define SSL_DIRECTION_SEND 0
#define SSL_DIRECTION_RECV 1

// Actions — written into the ring buffer so userspace can log them
#define ACTION_ALLOW 0
#define ACTION_BLOCK 1

// struct event layout (328 bytes):
// [0:8]   timestamp_ns
// [8:12]  pid
// [12:16] tgid
// [16:20] ppid  (NEW)
// [20]    event_type
// [21]    action
// [22:24] _pad
// [24:40] comm
// [40:296] path
// [296:300] dest_ip4
// [300:316] dest_ip6
// [316:318] dest_port
// [318]   is_ipv6
// [319]   _pad2
// [320:324] profile_id (NEW — Phase 6 slice D: active profile at hook time, 0 = no entry)
// [324:328] epoch      (NEW — tool-switch epoch, 0 = baseline)
// Total: 328 bytes (append-only: first 320 bytes unchanged, so the current
// Go decoder keeps working until it learns the tail)
struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;      // parent PID (NEW)
	__u8 event_type; // EVENT_*
	__u8 action;     // ACTION_*
	__u8 _pad[2];

	char comm[MAX_COMM_LEN];

	// FileOpen / Exec
	char path[MAX_PATH_LEN];

	// NetConnect
	__u32 dest_ip4; // network byte order
	__u8 dest_ip6[16];
	__u16 dest_port; // host byte order
	__u8 is_ipv6;
	__u8 _pad2;

	// Phase 6 slice D: filled from CGROUP_STATE at hook time (0/0 when
	// the current cgroup has no entry — today's behavior unchanged).
	__u32 profile_id;
	__u32 epoch;
};

// ssl_event layout (4140 bytes):
// [0:8]   timestamp_ns
// [8:12]  pid
// [12:16] tgid
// [16:20] ppid
// [20]    direction
// [21:24] _pad
// [24:40] comm
// [40:44] data_len
// [44:4140] data
// Total: 4140 bytes
struct ssl_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u8 direction;
	__u8 _pad[3];
	char comm[MAX_COMM_LEN];
	__u32 data_len;
	char data[MAX_SSL_BUF];
};

// CGROUP_STATE value (spec §8.2, Phase 6 slice D): key is the cgroup v2 id
// (u64, from bpf_get_current_cgroup_id — the inode of
// /sys/fs/cgroup/aks/<agent>). Hooks read it to pick the active profile;
// v1 concurrency is one tool per agent, so one entry per agent cgroup.
struct cgroup_state {
	__u32 profile_id;
	__u32 epoch;
	__u32 flags;
};

// COUNTERS key space (spec §8.2, FR-9): key = (hook << 2) | verdict.
// Hooks are numbered per LSM program, independent of EVENT_* (a hook and an
// event type are different things: e.g. socket_connect vs net_connect).
#define HOOK_FILE_OPEN 0
#define HOOK_SOCKET_CONNECT 1
#define HOOK_BPRM_CHECK 2

// Counter verdicts. Only DENY and DROP are bumped (see counters map comment);
// ALLOW is reserved in the key space, not counted on the hot path.
#define CTR_ALLOW 0
#define CTR_DENY 1
#define CTR_DROP 2
