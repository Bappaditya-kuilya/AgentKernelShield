package profiles_test

import (
	"net"
	"testing"

	"github.com/Bappaditya-kuilya/aks/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadOllama(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := profiles.LoadFile("../../profiles/ollama.yaml")
	require.NoError(t, err)
	return p
}

// ── Profile loading ─────────────────────────────────────────────────────────

func TestLoad_ValidFile(t *testing.T) {
	p := loadOllama(t)
	assert.Equal(t, "ollama", p.Name)
	assert.NotEmpty(t, p.DeniedPaths)
	assert.NotEmpty(t, p.AllowedPaths)
	assert.NotEmpty(t, p.AllowedNetworks)
	assert.NotEmpty(t, p.AllowedCommands)
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := profiles.LoadFile("nonexistent.yaml")
	assert.Error(t, err)
}

func TestLoad_InvalidCIDR(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
name: bad
allowed_networks:
  - not-a-cidr
`))
	assert.Error(t, err)
}

// ── File path matching ───────────────────────────────────────────────────────

func TestMatchPath_DeniedExact(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictDeny, p.MatchPath(path), "expected DENY for %s", path)
	}
}

func TestMatchPath_DeniedGlob(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/root/.ssh/id_rsa",
		"/home/alice/.ssh/authorized_keys",
		"/home/bob/.ssh/id_ed25519",
		"/etc/sudoers.d/nopasswd",
		"/proc/1234/mem",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictDeny, p.MatchPath(path), "expected DENY for %s", path)
	}
}

func TestMatchPath_AllowedOllamaModel(t *testing.T) {
	p := loadOllama(t)
	cases := []string{
		"/home/alice/.ollama/models/sha256-abc123",
		"/root/.ollama/models/llama3/config.json",
		"/tmp/ollama_blobs",
	}
	for _, path := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchPath(path), "expected ALLOW for %s", path)
	}
}

func TestMatchPath_DefaultDeny_UnknownPath(t *testing.T) {
	p := loadOllama(t)
	// A path not in any rule should fall back to default policy (deny)
	v := p.MatchPath("/opt/someapp/data/file.bin")
	assert.Equal(t, profiles.VerdictDefault, v)
	assert.True(t, p.DefaultDeny())
}

// ── Network matching ─────────────────────────────────────────────────────────

func TestMatchIP_LocahostAllowed(t *testing.T) {
	p := loadOllama(t)
	cases := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.2"),
		net.ParseIP("::1"),
	}
	for _, ip := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchIP(ip), "expected ALLOW for %s", ip)
	}
}

func TestMatchIP_ExternalDenied(t *testing.T) {
	p := loadOllama(t)
	cases := []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("192.168.1.100"),
		net.ParseIP("10.0.0.1"),
	}
	for _, ip := range cases {
		assert.Equal(t, profiles.VerdictDefault, p.MatchIP(ip), "expected DEFAULT(→deny) for %s", ip)
	}
}

// ── Default policy ───────────────────────────────────────────────────────────

func TestDefaultDeny_AllowPolicy(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: permissive
default_policy: allow
allowed_networks:
  - 127.0.0.0/8
`))
	require.NoError(t, err)
	assert.False(t, p.DefaultDeny())
}

// ── Deny takes precedence over allow ─────────────────────────────────────────

func TestMatchPath_DenyBeforeAllow(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
denied_paths:
  - /etc/passwd
allowed_paths:
  - /etc/**
`))
	require.NoError(t, err)
	// /etc/passwd matches both denied and allowed; denied must win
	assert.Equal(t, profiles.VerdictDeny, p.MatchPath("/etc/passwd"))
	// /etc/hosts is only in allowed
	assert.Equal(t, profiles.VerdictAllow, p.MatchPath("/etc/hosts"))
}

// ── watched_comms ─────────────────────────────────────────────────────────────

func TestWatchComm_EmptyListWatchesAll(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`name: test`))
	require.NoError(t, err)
	for _, comm := range []string{"node", "systemd", "anything"} {
		assert.True(t, p.WatchComm(comm), "empty watched_comms should watch %s", comm)
	}
}

func TestWatchComm_MatchesListed(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
watched_comms: [node, bun, gemini]
`))
	require.NoError(t, err)
	assert.True(t, p.WatchComm("node"))
	assert.True(t, p.WatchComm("bun"))
	assert.True(t, p.WatchComm("gemini"))
}

func TestWatchComm_RejectsUnlisted(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
watched_comms: [node, bun]
`))
	require.NoError(t, err)
	for _, comm := range []string{"systemd", "sshd", "dockerd", "cron"} {
		assert.False(t, p.WatchComm(comm), "should not watch %s", comm)
	}
}

// ── entry_comm ───────────────────────────────────────────────────────────────

func TestWatchComm_EntryComm_WatchesAll(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: test
entry_comm: gemini
watched_comms: [node, bun]
`))
	require.NoError(t, err)
	// When entry_comm is set, BPF handles lineage filtering.
	// WatchComm must return true for any comm so Go doesn't double-filter.
	for _, comm := range []string{"node", "bun", "systemd", "sshd", "sh", "python3"} {
		assert.True(t, p.WatchComm(comm), "entry_comm active: should watch %s", comm)
	}
}

func TestLoad_EntryComm(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: gemini-cli
entry_comm: gemini
`))
	require.NoError(t, err)
	assert.Equal(t, "gemini", p.EntryComm)
}

func TestEntryComm_LengthValidation(t *testing.T) {
	// Kernel TASK_COMM_LEN is 16 including NUL: entry_comm longer than
	// 15 chars truncates without NUL so kernel matching never hits.
	tests := []struct {
		name    string
		yaml    string
		comm    string
		wantErr bool
	}{
		{name: "empty ok", yaml: "name: test\n", comm: "", wantErr: false},
		{name: "empty string ok", yaml: "name: test\nentry_comm: \"\"\n", comm: "", wantErr: false},
		{name: "15 ok", yaml: "name: test\nentry_comm: \"123456789012345\"\n", comm: "123456789012345", wantErr: false},
		{name: "16 rejected", yaml: "name: test\nentry_comm: \"1234567890123456\"\n", wantErr: true},
		{name: "long rejected", yaml: "name: test\nentry_comm: \"averylongprocessname\"\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profiles.LoadBytes([]byte(tt.yaml))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "line")
				assert.Contains(t, err.Error(), "entry_comm")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.comm, p.EntryComm)
		})
	}
}

func TestEntryComm_ScopesLSMEnforcement(t *testing.T) {
	// When entry_comm is set, BPF LSM hooks check watched_pids before blocking.
	// This ensures enforcement is scoped to the agent's process tree only —
	// system processes (sudo, sshd, cron) are never blocked even if their
	// file access matches a denied_paths rule.
	//
	// This is verified at the profile level by confirming entry_comm is set
	// in all agent profiles. The BPF pid_is_watched() guard in lsm.c enforces it.
	agentProfiles := []string{
		"../../profiles/gemini-cli.yaml",
		"../../profiles/claude-code.yaml",
	}
	for _, path := range agentProfiles {
		p, err := profiles.LoadFile(path)
		require.NoError(t, err, path)
		assert.NotEmpty(t, p.EntryComm,
			"%s: entry_comm must be set so LSM enforcement is scoped to the agent process tree", path)
	}
}

// ── Command matching ─────────────────────────────────────────────────────────

func TestMatchCommand_AllowedRunners(t *testing.T) {
	p := loadOllama(t)
	cases := []string{"ollama", "llama-runner", "ollama-runner"}
	for _, cmd := range cases {
		assert.Equal(t, profiles.VerdictAllow, p.MatchCommand(cmd), "expected ALLOW for %s", cmd)
	}
}

func TestMatchCommand_FullPathStrippedToBasename(t *testing.T) {
	p := loadOllama(t)
	assert.Equal(t, profiles.VerdictAllow, p.MatchCommand("/usr/local/bin/ollama"))
}

func TestMatchCommand_ShellDenied(t *testing.T) {
	p := loadOllama(t)
	cases := []string{"bash", "sh", "python3", "curl", "wget", "nc"}
	for _, cmd := range cases {
		assert.Equal(t, profiles.VerdictDeny, p.MatchCommand(cmd), "expected DENY for %s", cmd)
	}
}

func TestMatchCommand_EmptyListDefersToDefault(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`name: test`))
	require.NoError(t, err)
	// With no allowed_commands list, every command defers to the default
	// policy so exec behavior is identical to path-only evaluation.
	assert.Equal(t, profiles.VerdictDefault, p.MatchCommand("/bin/bash"))
	assert.Equal(t, profiles.VerdictDefault, p.MatchCommand("ollama"))
}
