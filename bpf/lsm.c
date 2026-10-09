// go:build ignore
//  LSM BPF hooks — compiled separately, requires CONFIG_BPF_LSM=y and lsm=bpf boot param.
//  These hooks run synchronously BEFORE the syscall completes, enabling true inline blocking.
//  Verdict contract (spec FR-11, G3): return 0 means "no opinion" and never
//  clears another LSM's deny — BPF LSM denies if ANY program returns non-zero.
//  Return -1 only when our denylist matched or a fail-closed trigger below fires.
//  Every "return 0" below carries a comment justifying the allow (final-verification grep).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

// ── Shared maps (must match probe.c definitions) ─────────────────────────────

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events __weak SEC(".maps");

// Block-list for file paths: key = exact path string, value = 1
// Populated by the Go daemon from the profile's denied_paths list.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, char[MAX_PATH_LEN]);
	__type(value, __u8);
} blocked_paths SEC(".maps");

// Block-list for IPv4 addresses: key = __u32 network byte order, value = 1
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} blocked_ipv4 SEC(".maps");

// Block-list for IPv6 addresses: key = 16 raw network-order bytes, value = 1
// Populated reactively by the Go daemon via BlockIP (same model as blocked_ipv4).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[IPV6_LEN]);
	__type(value, __u8);
} blocked_ipv6 SEC(".maps");

// CGROUP_STATE (spec §8.2, Phase 6 slice D): key = cgroup v2 id from
// bpf_get_current_cgroup_id() (== inode of /sys/fs/cgroup/aks/<agent>),
// value = active profile + tool-switch epoch. Populated by the Go daemon
// (SeedCgroupState); a missing entry means fall through to current behavior
// unchanged, so today's profiles keep working with an empty map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, struct cgroup_state);
} cgroup_state SEC(".maps");

// Per-cpu scratch buffer for normalising the bpf_d_path result.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH_LEN]);
} path_scratch SEC(".maps");

// watched_pids: shared with probe.c — only enforce against agent process tree.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} watched_pids __weak SEC(".maps");

// entry_comm: shared with probe.c — detect when lineage filtering is active.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_COMM_LEN]);
} entry_comm __weak SEC(".maps");

// COUNTERS (spec §8.2, FR-9): per-CPU counts keyed (hook << 2) | verdict.
// Packed into one __u32 so the map stays a PERCPU_ARRAY (array keys must be
// 4 bytes; max key (2<<2)|2 = 10 < 16 entries). Only DENY and DROP are
// bumped — ALLOW is the hot path (every open/connect of every watched
// process) and counting it would cost overhead against G4 for no value.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

// ── Helpers ───────────────────────────────────────────────────────────────────

// pid_is_watched mirrors the same helper in probe.c.
// When entry_comm is unconfigured (first byte '\0'), all PIDs pass — meaning
// enforcement applies to every process (safe default when no lineage data).
// When entry_comm is set, only PIDs in watched_pids are enforced — so aks
// only blocks the agent's own process tree, leaving sudo, sshd, etc. alone.
static __always_inline int pid_is_watched(__u32 pid)
{
	__u32 z = 0;
	char *entry = bpf_map_lookup_elem(&entry_comm, &z);
	if (!entry || entry[0] == '\0')
		return 1; // no lineage configured — enforce all (safe default)
	return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

static __always_inline void count(__u32 hook, __u32 verdict)
{
	__u32 key = (hook << 2) | verdict;
	__u64 *val = bpf_map_lookup_elem(&counters, &key);
	if (val)
		(*val)++;
}

// stash_cgroup_state reads CGROUP_STATE for the current cgroup into
// *profile_id/*epoch (callers zero them first; a missing entry leaves them
// 0/0 = baseline). Verdict logic never branches on state in v1 (one tool per
// agent) — the stashed values are only carried in emitted events.
static __always_inline void stash_cgroup_state(__u32 *profile_id, __u32 *epoch)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct cgroup_state *st = bpf_map_lookup_elem(&cgroup_state, &cgid);
	if (st) {
		*profile_id = st->profile_id;
		*epoch = st->epoch;
	}
}

// deny_with_path emits a best-effort BLOCK event for a path-based hook and
// always returns -1 (deny). path may be NULL (resolution failed) — the event
// then carries a zeroed path. Ringbuf-full still denies and bumps the drop
// counter instead of denying silently (spec FR-9, G3).
static __always_inline int deny_with_path(__u32 hook, __u32 type, const char *path,
					  __u32 profile_id, __u32 epoch)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(hook, CTR_DROP);
		return -1;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = type;
	e->action = ACTION_BLOCK;
	e->pid = (__u32)(pid_tgid >> 32);
	e->tgid = (__u32)pid_tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (path)
		__builtin_memcpy(e->path, path, MAX_PATH_LEN);
	e->profile_id = profile_id;
	e->epoch = epoch;
	bpf_ringbuf_submit(e, 0);
	count(hook, CTR_DENY);
	return -1;
}

// ── LSM: file_open ────────────────────────────────────────────────────────────

SEC("lsm/file_open")
int BPF_PROG(aks_file_open, struct file *file)
{
	// CGROUP_STATE first: missing entry leaves 0/0 and falls through to
	// current behavior unchanged (FR-11 verdict logic below untouched).
	__u32 profile_id = 0, epoch = 0;
	stash_cgroup_state(&profile_id, &epoch);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0; // not our agent tree — no opinion, never override other LSMs (FR-11)

	char path[MAX_PATH_LEN] = {};
	// Fail closed (G3): an unresolvable path cannot be checked against the
	// denylist, so deny with a pathless event. Never allow here.
	if (bpf_d_path(&file->f_path, path, sizeof(path)) <= 0)
		return deny_with_path(HOOK_FILE_OPEN, EVENT_FILE_OPEN, NULL, profile_id, epoch);

	__u32 z = 0;
	char *key = bpf_map_lookup_elem(&path_scratch, &z);
	// Fail closed (G3): without scratch we cannot normalise the path for
	// lookup — deny carrying the raw path. Never allow here.
	if (!key)
		return deny_with_path(HOOK_FILE_OPEN, EVENT_FILE_OPEN, path, profile_id, epoch);
	__builtin_memset(key, 0, MAX_PATH_LEN);
	for (int i = 0; i < MAX_PATH_LEN; i++) {
		char c = path[i];
		key[i] = c;
		if (!c)
			break;
	}

	__u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
	if (!blocked)
		return 0; // denylist miss — no opinion, never override other LSMs (FR-11)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(HOOK_FILE_OPEN, CTR_DROP);
		return -1; // ringbuf full: still deny, drop counted (FR-9)
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_FILE_OPEN;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->path, key, MAX_PATH_LEN);
	e->profile_id = profile_id;
	e->epoch = epoch;
	bpf_ringbuf_submit(e, 0);
	count(HOOK_FILE_OPEN, CTR_DENY);
	return -1; // kernel maps -1 → -EPERM for LSM deny
}

// ── LSM: socket_connect ───────────────────────────────────────────────────────

SEC("lsm/socket_connect")
int BPF_PROG(aks_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	// CGROUP_STATE first: missing entry leaves 0/0 and falls through to
	// current behavior unchanged (FR-11 verdict logic below untouched).
	__u32 profile_id = 0, epoch = 0;
	stash_cgroup_state(&profile_id, &epoch);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0; // not our agent tree — no opinion, never override other LSMs (FR-11)

	// Non-IP families (e.g. AF_UNIX) stay out of scope — no opinion (FR-11).
	if (address->sa_family != AF_INET && address->sa_family != AF_INET6)
		return 0;

	// Phase 4: IPv6 denylist mirror of the IPv4 path below. Loopback and any
	// non-blocked v6 destination falls through to allow — the Go detector
	// applies the profile's allowlist from the decoded event.
	if (address->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		char v6key[IPV6_LEN] = {};
		bpf_probe_read_kernel(v6key, sizeof(v6key), &sin6->sin6_addr);

		__u8 *blocked6 = bpf_map_lookup_elem(&blocked_ipv6, v6key);
		if (!blocked6)
			return 0; // v6 denylist miss — no opinion, never override other LSMs (FR-11)

		struct task_struct *task6 = (struct task_struct *)bpf_get_current_task();

		struct event *e6 = bpf_ringbuf_reserve(&events, sizeof(*e6), 0);
		if (!e6) {
			count(HOOK_SOCKET_CONNECT, CTR_DROP);
			return -1; // ringbuf full: still deny, drop counted (FR-9)
		}
		__builtin_memset(e6, 0, sizeof(*e6));
		e6->timestamp_ns = bpf_ktime_get_ns();
		e6->event_type = EVENT_NET_CONNECT;
		e6->action = ACTION_BLOCK;
		e6->pid = pid;
		e6->tgid = (__u32)bpf_get_current_pid_tgid();
		e6->ppid = BPF_CORE_READ(task6, real_parent, tgid);
		bpf_get_current_comm(&e6->comm, sizeof(e6->comm));
		__builtin_memcpy(e6->dest_ip6, v6key, IPV6_LEN);
		e6->dest_port = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
		e6->is_ipv6 = 1;
		e6->profile_id = profile_id;
		e6->epoch = epoch;
		bpf_ringbuf_submit(e6, 0);
		count(HOOK_SOCKET_CONNECT, CTR_DENY);

		return -1; // -EPERM
	}

	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	__u32 dest_ip = BPF_CORE_READ(sin, sin_addr.s_addr);

	__u8 *blocked = bpf_map_lookup_elem(&blocked_ipv4, &dest_ip);
	if (!blocked)
		return 0; // denylist miss — no opinion, never override other LSMs (FR-11)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(HOOK_SOCKET_CONNECT, CTR_DROP);
		return -1; // ringbuf full: still deny, drop counted (FR-9)
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_NET_CONNECT;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->dest_ip4 = dest_ip;
	e->dest_port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->profile_id = profile_id;
	e->epoch = epoch;
	bpf_ringbuf_submit(e, 0);
	count(HOOK_SOCKET_CONNECT, CTR_DENY);

	return -1; // -EPERM
}

// ── LSM: bprm_check_security ─────────────────────────────────────────────────

SEC("lsm/bprm_check_security")
int BPF_PROG(aks_bprm_check, struct linux_binprm *bprm)
{
	// CGROUP_STATE first: missing entry leaves 0/0 and falls through to
	// current behavior unchanged (FR-11 verdict logic below untouched).
	__u32 profile_id = 0, epoch = 0;
	stash_cgroup_state(&profile_id, &epoch);

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!pid_is_watched(pid))
		return 0; // not our agent tree — no opinion, never override other LSMs (FR-11)

	char path[MAX_PATH_LEN] = {};
	// Fail closed (G3): an unresolvable path cannot be checked against the
	// denylist, so deny with a pathless event. Never allow here.
	if (bpf_d_path(&bprm->file->f_path, path, sizeof(path)) <= 0)
		return deny_with_path(HOOK_BPRM_CHECK, EVENT_EXEC, NULL, profile_id, epoch);

	__u32 z = 0;
	char *key = bpf_map_lookup_elem(&path_scratch, &z);
	// Fail closed (G3): without scratch we cannot normalise the path for
	// lookup — deny carrying the raw path. Never allow here.
	if (!key)
		return deny_with_path(HOOK_BPRM_CHECK, EVENT_EXEC, path, profile_id, epoch);
	__builtin_memset(key, 0, MAX_PATH_LEN);
	for (int i = 0; i < MAX_PATH_LEN; i++) {
		char c = path[i];
		key[i] = c;
		if (!c)
			break;
	}

	__u8 *blocked = bpf_map_lookup_elem(&blocked_paths, key);
	if (!blocked)
		return 0; // denylist miss — no opinion, never override other LSMs (FR-11)

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(HOOK_BPRM_CHECK, CTR_DROP);
		return -1; // ringbuf full: still deny, drop counted (FR-9)
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = EVENT_EXEC;
	e->action = ACTION_BLOCK;
	e->pid = pid;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->path, key, MAX_PATH_LEN);
	e->profile_id = profile_id;
	e->epoch = epoch;
	bpf_ringbuf_submit(e, 0);
	count(HOOK_BPRM_CHECK, CTR_DENY);

	return -1; // -EPERM
}
