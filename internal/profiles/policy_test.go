package profiles_test

import (
	"strings"
	"testing"

	"github.com/Bappaditya-kuilya/aks/internal/profiles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validFullPolicy = `
version: 1
name: research-bot
default: deny
baseline:
  exec: [/usr/bin/python3]
  net: ["api.example-llm.com:443"]
  fs: read_write
  deny_files: [~/.ssh, ~/.aws, .env]
tools:
  read_docs:
    fs: read_only
    net: []
  write_report:
    fs: read_write
    exec: []
restricted:
  fs: read_only
`

func TestPolicy_FullSchemaValid(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(validFullPolicy))
	require.NoError(t, err)
	assert.Equal(t, "research-bot", p.Name)
	assert.Equal(t, "1", string(p.Version))
	assert.Equal(t, "deny", p.Default)
	require.NotNil(t, p.Baseline)
	assert.Equal(t, []string{"/usr/bin/python3"}, p.Baseline.Exec)
	assert.Equal(t, []string{"api.example-llm.com:443"}, p.Baseline.Net)
	assert.Equal(t, "read_write", p.Baseline.Fs)
	require.NotNil(t, p.Restricted)
	assert.Equal(t, "read_only", p.Restricted.Fs)
	require.Contains(t, p.Tools, "read_docs")
	require.Contains(t, p.Tools, "write_report")
	assert.True(t, p.DefaultDeny())
}

func TestPolicy_EffectiveSet(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(validFullPolicy))
	require.NoError(t, err)
	// Baseline + tool additions; tool fs wins; deny_files always applies.
	assert.Equal(t, []string{"/usr/bin/python3"}, p.EffectiveExec("read_docs"))
	assert.Equal(t, []string{"api.example-llm.com:443"}, p.EffectiveNet("read_docs"))
	assert.Equal(t, "read_only", p.EffectiveFS("read_docs"))
	assert.Equal(t, "read_write", p.EffectiveFS("write_report"))
	assert.Equal(t, "read_write", p.EffectiveFS("baseline"))
	assert.Equal(t, "read_only", p.EffectiveFS("unknown-tool"))
	assert.Equal(t, []string{"~/.ssh", "~/.aws", ".env"}, p.EffectiveDenyFiles())
}

func TestPolicy_DefaultDeny_NewSchema(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(validFullPolicy))
	require.NoError(t, err)
	assert.True(t, p.DefaultDeny())
}

func TestPolicy_UnknownTopLevelKey(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
bogus_key: 1
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_UnknownBaselineKey(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
  bogus: 1
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_UnknownToolKey(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
tools:
  mytool:
    fs: read_only
    bogus: 1
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_BadFSBaseline(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: banana
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
	assert.Contains(t, err.Error(), "banana")
}

func TestPolicy_BadFSTool(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
tools:
  mytool:
    fs: WRONG
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_BadFSRestricted(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
restricted:
  fs: rw
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_MalformedNetBaseline(t *testing.T) {
	for _, bad := range []string{"noport", "host:", ":443", "host:abc", "host:0", "host:99999", "ho st:443"} {
		_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
  net: ["` + bad + `"]
restricted:
  fs: read_only
`))
		require.Error(t, err, "net %q must be rejected", bad)
		assert.Contains(t, err.Error(), "line")
	}
}

func TestPolicy_MalformedNetTool(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: x
default: deny
baseline:
  fs: read_write
tools:
  mytool:
    fs: read_only
    net: ["good.example.com:443", "bad-entry"]
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
	assert.True(t, strings.Contains(err.Error(), "mytool") || strings.Contains(err.Error(), "bad-entry"))
}

func TestPolicy_EmptyName(t *testing.T) {
	_, err := profiles.LoadBytes([]byte(`
version: 1
name: ""
default: deny
baseline:
  fs: read_write
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")

	_, err = profiles.LoadBytes([]byte(`
version: 1
default: deny
baseline:
  fs: read_write
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

func TestPolicy_VersionMismatch(t *testing.T) {
	// Wrong int version with new schema.
	_, err := profiles.LoadBytes([]byte(`
version: 2
name: x
default: deny
baseline:
  fs: read_write
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")

	// Legacy string version with new schema.
	_, err = profiles.LoadBytes([]byte(`
version: "1.0"
name: x
default: deny
baseline:
  fs: read_write
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")

	// Missing version with new schema.
	_, err = profiles.LoadBytes([]byte(`
name: x
default: deny
baseline:
  fs: read_write
restricted:
  fs: read_only
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line")
}

// ── Backwards compatibility: legacy yamls must keep loading ────────────────

func TestPolicy_LegacyYamlsStillLoad(t *testing.T) {
	for _, path := range []string{
		"../../profiles/ollama.yaml",
		"../../profiles/gemini-cli.yaml",
		"../../profiles/claude-code.yaml",
	} {
		p, err := profiles.LoadFile(path)
		require.NoError(t, err, path)
		assert.NotEmpty(t, p.Name, path)
	}
}

func TestPolicy_LegacyMinimalStillLoads(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`name: test`))
	require.NoError(t, err)
	assert.Equal(t, "test", p.Name)
}

func TestPolicy_LegacyVersionStringStillLoads(t *testing.T) {
	p, err := profiles.LoadBytes([]byte(`
name: ollama
version: "1.0"
default_policy: deny
`))
	require.NoError(t, err)
	assert.Equal(t, "1.0", string(p.Version))
	assert.True(t, p.DefaultDeny())
}
