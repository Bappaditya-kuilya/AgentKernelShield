//go:build linux

package loader

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── cmdlineMatchesEntry ───────────────────────────────────────────────────────

func TestCmdlineMatchesEntry_basenameMatch(t *testing.T) {
	l := &Loader{entryComm: "gemini"}
	cases := []struct {
		raw  string
		want bool
	}{
		// Shebang script invoked via node: argv contains /usr/bin/gemini.
		{"node\x00--no-warnings=DEP0040\x00/usr/bin/gemini\x00", true},
		// Direct binary execution.
		{"gemini\x00", true},
		// Full path with no other args.
		{"/usr/bin/gemini\x00", true},
		// Unrelated process.
		{"python3\x00script.py\x00", false},
		// Prefix match must not trigger (gemini-cli ≠ gemini).
		{"node\x00/usr/bin/gemini-cli\x00", false},
		// Node without gemini.
		{"node\x00/usr/bin/ollama\x00", false},
	}
	for _, tc := range cases {
		got := cmdlineMatchesEntryStr(l.entryComm, tc.raw)
		assert.Equal(t, tc.want, got, "cmdline=%q", tc.raw)
	}
}

func TestCmdlineMatchesEntry_emptyEntryComm(t *testing.T) {
	l := &Loader{entryComm: ""}
	// Empty entry_comm → never matches (lineage tracking disabled).
	assert.False(t, cmdlineMatchesEntryStr(l.entryComm, "gemini\x00"))
}

// TestExpandDeniedPaths_GlobMatchesFiles verifies a glob denied_paths entry
// expands to one exact key per concrete match (the BPF map only does
// exact-match lookups, so literal "**" keys would never match).
func TestExpandDeniedPaths_GlobMatchesFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	require.NoError(t, os.WriteFile(a, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("b"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.log"), []byte("c"), 0o600))

	// Single-level pattern goes through stdlib filepath.Glob.
	got := expandDeniedPaths(filepath.Join(dir, "*.txt"))
	assert.ElementsMatch(t, []string{a, b}, got)
}

// TestExpandDeniedPaths_DoubleStarMatchesNested verifies the doublestar
// branch: ** recursion reaches files in subdirectories.
func TestExpandDeniedPaths_DoubleStarMatchesNested(t *testing.T) {
	dir := t.TempDir()
	top := filepath.Join(dir, "top.txt")
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	nested := filepath.Join(sub, "nested.txt")
	require.NoError(t, os.WriteFile(top, []byte("t"), 0o600))
	require.NoError(t, os.WriteFile(nested, []byte("n"), 0o600))

	got := expandDeniedPaths(filepath.Join(dir, "**", "*.txt"))
	assert.ElementsMatch(t, []string{top, nested}, got)
}

// TestExpandDeniedPaths_NoMatchSkipped verifies a pattern matching nothing
// yields no keys (fail-open for that rule, with a stderr warning).
func TestExpandDeniedPaths_NoMatchSkipped(t *testing.T) {
	dir := t.TempDir()
	got := expandDeniedPaths(filepath.Join(dir, "*.nomatch"))
	assert.Empty(t, got)
}

// TestExpandDeniedPaths_LiteralUnchanged verifies entries without glob
// metacharacters keep the current verbatim behavior.
func TestExpandDeniedPaths_LiteralUnchanged(t *testing.T) {
	assert.Equal(t, []string{"/etc/passwd"}, expandDeniedPaths("/etc/passwd"))
}

// TestBootWallTime verifies that bootWallTime() returns a time in the past
// (the system booted before now) and is within a reasonable range.
func TestBootWallTime(t *testing.T) {
	before := time.Now()
	bt := bootWallTime()
	after := time.Now()

	assert.True(t, bt.Before(before), "boot time must be before the call")
	assert.True(t, bt.After(after.Add(-30*24*time.Hour)), "boot time must be within the last 30 days")
}

// TestDecodeEvent_fields verifies that every field is read from the correct
// byte offset in the 320-byte struct event layout.
func TestDecodeEvent_fields(t *testing.T) {
	raw := make([]byte, 320)

	// [0:8]    timestamp_ns = 1_000_000_000 (1 second)
	const oneSecNs = uint64(1e9)
	for i := range 8 {
		raw[i] = byte(oneSecNs >> (8 * i))
	}

	// [8:12]   pid = 1234
	binary.LittleEndian.PutUint32(raw[8:12], 1234)
	// [12:16]  tgid = 5678 (unused)
	binary.LittleEndian.PutUint32(raw[12:16], 5678)
	// [16:20]  ppid = 999
	binary.LittleEndian.PutUint32(raw[16:20], 999)
	// [20]     event_type = 0 (FileOpen)
	raw[20] = 0
	// [24:40]  comm = "ollama"
	copy(raw[24:40], "ollama\x00")
	// [40:296] path = "/etc/passwd"
	copy(raw[40:296], "/etc/passwd\x00")
	// [296:300] dest_ip4 = 8.8.8.8 in network byte order
	raw[296], raw[297], raw[298], raw[299] = 8, 8, 8, 8
	// [316:318] dest_port = 443
	binary.LittleEndian.PutUint16(raw[316:318], 443)

	knownBoot := time.Unix(0, 0) // epoch as boot time for easy arithmetic
	e, err := decodeEvent(raw, knownBoot)
	require.NoError(t, err)

	assert.Equal(t, uint32(1234), e.PID, "pid")
	assert.Equal(t, uint32(999), e.PPID, "ppid")
	assert.Equal(t, uint8(0), uint8(e.Type), "event_type")
	assert.Equal(t, "ollama", e.Comm, "comm")
	assert.Equal(t, "/etc/passwd", e.Path, "path")
	assert.Equal(t, uint16(443), e.DestPort, "dest_port")
	assert.NotNil(t, e.DestIP, "dest_ip should be set")
	assert.Equal(t, "8.8.8.8", e.DestIP.String(), "dest_ip value")
	// timestamp = boot(epoch) + 1s = Unix second 1
	assert.Equal(t, int64(1), e.Timestamp.Unix(), "timestamp")
}

// walkTestTree builds a real directory tree for walk tests: pseudo-fs lookalikes,
// real credential dirs, a nested same-named dir, and a symlink cycle.
func walkTestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mkfile := func(rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	}
	mkfile("proc/self/exe")
	mkfile("sys/kernel/x")
	mkfile("dev/null")
	mkfile("home/alice/.aws/credentials")
	mkfile("home/alice/dev/keep.txt")
	mkfile("opt/data/.aws/config")
	mkfile("a/real.txt")
	mkfile("b/real.txt")
	require.NoError(t, os.Symlink("../b", filepath.Join(root, "a", "loop")))
	require.NoError(t, os.Symlink("../a", filepath.Join(root, "b", "loop")))
	return root
}

// TestWalkCollect_SkipsPseudoFS verifies top-level proc/sys/dev are pruned.
// Regression test for the CI micro-VM hang: /**/ patterns walked the entire
// shared host root (10-minute go test timeout inside expandDeniedPaths →
// doublestar FilepathGlob, proven by the CI stack trace; the first GlobWalk
// attempt could not prune because its callback only fires for matches).
func TestWalkCollect_SkipsPseudoFS(t *testing.T) {
	root := walkTestTree(t)
	skip := map[string]bool{
		filepath.Join(root, "proc"): true,
		filepath.Join(root, "sys"):  true,
		filepath.Join(root, "dev"):  true,
	}
	got, err := walkCollect(root, filepath.Join(root, "**", ".aws", "**"), skip)
	require.NoError(t, err)
	for _, p := range got {
		assert.NotContains(t, p, string(filepath.Separator)+"proc"+string(filepath.Separator), "pseudo-fs must be pruned: %s", p)
		assert.NotContains(t, p, string(filepath.Separator)+"sys"+string(filepath.Separator), "pseudo-fs must be pruned: %s", p)
		assert.NotContains(t, p, string(filepath.Separator)+"dev"+string(filepath.Separator), "pseudo-fs must be pruned: %s", p)
	}
	assert.Contains(t, got, filepath.Join(root, "home", "alice", ".aws", "credentials"))
	assert.Contains(t, got, filepath.Join(root, "opt", "data", ".aws", "config"))
}

// TestWalkCollect_NestedSameNameWalks verifies pruning is top-level only:
// a nested directory named like a pseudo-fs still walks.
func TestWalkCollect_NestedSameNameWalks(t *testing.T) {
	root := walkTestTree(t)
	got, err := walkCollect(root, filepath.Join(root, "**", "keep.txt"), map[string]bool{})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "home", "alice", "dev", "keep.txt")}, got)
}

// TestWalkCollect_SymlinkCycleTerminates verifies symlinked dir loops cannot
// hang the walk (WalkDir never descends into symlinks): completion itself is
// the assertion.
func TestWalkCollect_SymlinkCycleTerminates(t *testing.T) {
	root := walkTestTree(t)
	done := make(chan []string, 1)
	go func() {
		got, err := walkCollect(root, filepath.Join(root, "**", "real.txt"), map[string]bool{})
		require.NoError(t, err)
		done <- got
	}()
	select {
	case got := <-done:
		assert.ElementsMatch(t, []string{
			filepath.Join(root, "a", "real.txt"),
			filepath.Join(root, "b", "real.txt"),
		}, got)
	case <-time.After(30 * time.Second):
		t.Fatal("walk did not terminate: symlink cycle followed")
	}
}

// TestWalkRoot verifies literal-prefix scoping: /**/ walks from /, prefixed
// patterns walk from their literal directory only.
func TestWalkRoot(t *testing.T) {
	assert.Equal(t, "/", walkRoot("/**/.aws/**"))
	assert.Equal(t, "/root/.ssh", walkRoot("/root/.ssh/**"))
	assert.Equal(t, "/home", walkRoot("/home/*/.ssh/**"))
	assert.Equal(t, "/etc", walkRoot("/etc/*.d/**"))
}

// TestExpandDeniedPaths_Memoized verifies repeat expansion returns equal
// results (process-lifetime snapshot shared across Loads).
func TestExpandDeniedPaths_Memoized(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o600))
	pattern := filepath.Join(dir, "*.txt")
	first := expandDeniedPaths(pattern)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o600))
	second := expandDeniedPaths(pattern)
	assert.Equal(t, first, second, "memoized snapshot must be stable within the process")
}

// TestDecodeEvent_tooShort verifies an error is returned for truncated input.
func TestDecodeEvent_tooShort(t *testing.T) {
	_, err := decodeEvent(make([]byte, 100), time.Now())
	assert.Error(t, err)
}

// TestDecodeEvent_ipv6 verifies dest_ip6/is_ipv6 decode: a real kernel
// net_connect event for an IPv6 destination must yield a 16-byte DestIP.
// Uses a non-palindrome address so byte-order bugs can't hide.
func TestDecodeEvent_ipv6(t *testing.T) {
	raw := make([]byte, 320)
	raw[20] = 1 // event_type = NetConnect
	copy(raw[24:40], "ollama\x00")
	// [300:316] dest_ip6 = 2001:db8::1234 (network order, verbatim)
	want := net.ParseIP("2001:db8::1234").To16()
	require.NotNil(t, want)
	copy(raw[300:316], want)
	// [316:318] dest_port = 443
	binary.LittleEndian.PutUint16(raw[316:318], 443)
	// [318] is_ipv6 = 1
	raw[318] = 1

	e, err := decodeEvent(raw, time.Unix(0, 0))
	require.NoError(t, err)
	require.NotNil(t, e.DestIP, "v6 dest_ip must decode")
	assert.Equal(t, "2001:db8::1234", e.DestIP.String(), "byte order must be preserved")
	assert.Equal(t, uint16(443), e.DestPort, "dest_port")
}

// TestDecodeEvent_ipv6Loopback verifies ::1 arrives via the real wire path
// (the detector ::1 test previously used a hand-built event that real
// kernel code couldn't produce).
func TestDecodeEvent_ipv6Loopback(t *testing.T) {
	raw := make([]byte, 320)
	raw[20] = 1 // event_type = NetConnect
	copy(raw[24:40], "ollama\x00")
	want := net.ParseIP("::1").To16()
	require.NotNil(t, want)
	copy(raw[300:316], want)
	binary.LittleEndian.PutUint16(raw[316:318], 11434)
	raw[318] = 1

	e, err := decodeEvent(raw, time.Unix(0, 0))
	require.NoError(t, err)
	require.NotNil(t, e.DestIP, "loopback must decode")
	assert.True(t, e.DestIP.Equal(net.ParseIP("::1")), "must be ::1")
}

// TestDecodeSSLEvent_fields verifies the ssl_event field layout.
func TestDecodeSSLEvent_fields(t *testing.T) {
	raw := make([]byte, 4140)

	// [0:8]    timestamp_ns = 2_000_000_000 (2 seconds)
	const twoSecNs = uint64(2e9)
	for i := range 8 {
		raw[i] = byte(twoSecNs >> (8 * i))
	}
	// [8:12]   pid = 7777
	binary.LittleEndian.PutUint32(raw[8:12], 7777)
	// [16:20]  ppid = 3333
	binary.LittleEndian.PutUint32(raw[16:20], 3333)
	// [20]     direction = 1 (SSLRecv)
	raw[20] = 1
	// [24:40]  comm = "claude"
	copy(raw[24:40], "claude\x00")
	// [40:44]  data_len = 12
	binary.LittleEndian.PutUint32(raw[40:44], 12)
	// [44:56]  data = "hello world!"
	copy(raw[44:], "hello world!")

	knownBoot := time.Unix(0, 0)
	e, err := decodeSSLEvent(raw, knownBoot)
	require.NoError(t, err)

	assert.Equal(t, uint32(7777), e.PID, "pid")
	assert.Equal(t, uint32(3333), e.PPID, "ppid")
	assert.Equal(t, uint8(1), uint8(e.Direction), "direction SSLRecv")
	assert.Equal(t, "claude", e.Comm, "comm")
	assert.Equal(t, "hello world!", e.Data, "data")
	assert.Equal(t, int64(2), e.Timestamp.Unix(), "timestamp")
}

// TestDecodeSSLEvent_dataLenCap verifies data_len > MAX_SSL_BUF is clamped.
func TestDecodeSSLEvent_dataLenCap(t *testing.T) {
	raw := make([]byte, 4140)
	// data_len = 99999 (exceeds MAX_SSL_BUF=4096)
	binary.LittleEndian.PutUint32(raw[40:44], 99999)
	copy(raw[44:], make([]byte, 4096)) // zeros

	e, err := decodeSSLEvent(raw, time.Now())
	require.NoError(t, err)
	// Should clamp to available buf, not crash
	assert.LessOrEqual(t, len(e.Data), 4096)
}

// TestDecodeSSLEvent_tooShort verifies an error is returned for truncated input.
func TestDecodeSSLEvent_tooShort(t *testing.T) {
	_, err := decodeSSLEvent(make([]byte, 10), time.Now())
	assert.Error(t, err)
}

// TestDecodeEvent_timestampUsesWallClock verifies that a BPF monotonic
// timestamp is correctly converted to a wall-clock time.
func TestDecodeEvent_timestampUsesWallClock(t *testing.T) {
	// Build a minimal raw event (320 bytes, all zero except timestamp).
	raw := make([]byte, 320)

	// Simulate a BPF event that fired 5 seconds after boot.
	fiveSecondsNs := uint64(5 * time.Second)
	raw[0] = byte(fiveSecondsNs)
	raw[1] = byte(fiveSecondsNs >> 8)
	raw[2] = byte(fiveSecondsNs >> 16)
	raw[3] = byte(fiveSecondsNs >> 24)
	raw[4] = byte(fiveSecondsNs >> 32)
	raw[5] = byte(fiveSecondsNs >> 40)
	raw[6] = byte(fiveSecondsNs >> 48)
	raw[7] = byte(fiveSecondsNs >> 56)

	// Use a known boot time 1 hour ago.
	knownBoot := time.Now().Add(-1 * time.Hour)
	e, err := decodeEvent(raw, knownBoot)
	require.NoError(t, err)

	expected := knownBoot.Add(5 * time.Second)
	assert.WithinDuration(t, expected, e.Timestamp, time.Millisecond,
		"event timestamp must be bootWallTime + 5s")
}

// TestDecodeEvent_timestampIsNotEpoch verifies the old bug is gone:
// timestamps must not be near the Unix epoch (Jan 1, 1970).
func TestDecodeEvent_timestampIsNotEpoch(t *testing.T) {
	raw := make([]byte, 320)

	// 2 hours of uptime in nanoseconds — typical value from bpf_ktime_get_ns.
	const twoHoursNs = uint64(2 * time.Hour)
	for i := range 8 {
		raw[i] = byte(twoHoursNs >> (8 * i))
	}

	bt := bootWallTime()
	e, err := decodeEvent(raw, bt)
	require.NoError(t, err)

	epoch := time.Unix(0, 0)
	assert.True(t, e.Timestamp.After(epoch.Add(24*time.Hour*365*10)),
		"timestamp must not be near Unix epoch (got %v)", e.Timestamp)
	assert.WithinDuration(t, time.Now(), e.Timestamp, 24*time.Hour,
		"timestamp must be close to now")
}

// TestDecodeEvent_cgroupAttributionTail verifies the 328-byte layout:
// bytes [320:328] decode into ProfileID/Epoch.
func TestDecodeEvent_cgroupAttributionTail(t *testing.T) {
	raw := make([]byte, 328)
	binary.LittleEndian.PutUint32(raw[8:12], 4321)
	binary.LittleEndian.PutUint32(raw[16:20], 1111)
	raw[20] = 0 // FileOpen
	copy(raw[24:40], "agent\x00")
	copy(raw[40:296], "/etc/shadow\x00")
	// [320:324] profile_id = 7, [324:328] epoch = 42
	binary.LittleEndian.PutUint32(raw[320:324], 7)
	binary.LittleEndian.PutUint32(raw[324:328], 42)

	e, err := decodeEvent(raw, time.Unix(0, 0))
	require.NoError(t, err)
	assert.Equal(t, uint32(7), e.ProfileID, "profile_id")
	assert.Equal(t, uint32(42), e.Epoch, "epoch")
	// Base fields still decode alongside the tail.
	assert.Equal(t, uint32(4321), e.PID, "pid")
	assert.Equal(t, "/etc/shadow", e.Path, "path")
}

// TestDecodeEvent_legacy320ZeroAttribution verifies backward compat:
// legacy 320-byte events decode with ProfileID/Epoch left zero.
func TestDecodeEvent_legacy320ZeroAttribution(t *testing.T) {
	raw := make([]byte, 320)
	binary.LittleEndian.PutUint32(raw[8:12], 4321)
	copy(raw[24:40], "agent\x00")
	copy(raw[40:296], "/etc/shadow\x00")

	e, err := decodeEvent(raw, time.Unix(0, 0))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), e.ProfileID, "legacy profile_id must be zero")
	assert.Equal(t, uint32(0), e.Epoch, "legacy epoch must be zero")
}
