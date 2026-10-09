package profiles

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// Verdict is the result of a profile rule evaluation.
type Verdict int

const (
	VerdictAllow   Verdict = iota // explicitly permitted by a rule
	VerdictDeny                   // explicitly denied by a rule
	VerdictDefault                // no rule matched; caller applies default policy
)

// PolicyVersion is the policy schema version. Legacy files use "1.0"
// (string); v1 tool-scoped policies use 1 (int). The custom unmarshaler
// accepts any scalar literal so legacy yamls keep loading.
type PolicyVersion string

// UnmarshalYAML accepts int, float and string scalars via their literal text.
func (v *PolicyVersion) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: version must be 1", n.Line)
	}
	if n.Tag == "!!null" {
		*v = ""
		return nil
	}
	*v = PolicyVersion(n.Value)
	return nil
}

// Baseline is the always-in-force profile (SPEC §9.1).
type Baseline struct {
	Exec      []string `yaml:"exec"`
	Net       []string `yaml:"net"`
	Fs        string   `yaml:"fs"`
	DenyFiles []string `yaml:"deny_files"`
}

// ToolPolicy narrows or extends the baseline for one named tool.
// Effective exec/net = baseline + tool additions; tool Fs wins;
// baseline deny_files always applies.
type ToolPolicy struct {
	Fs   string   `yaml:"fs"`
	Net  []string `yaml:"net"`
	Exec []string `yaml:"exec"`
}

// Restricted is the profile for unknown tools (fs read_only).
type Restricted struct {
	Fs string `yaml:"fs"`
}

// Profile defines the expected behavioral envelope for an AI inference process.
type Profile struct {
	Name        string        `yaml:"name"`
	Version     PolicyVersion `yaml:"version"`
	Description string        `yaml:"description"`

	// DefaultPolicy is applied when no rule matches ("allow" or "deny").
	DefaultPolicy string `yaml:"default_policy"`

	// EntryComm is the kernel comm of the agent's root process (e.g. "gemini",
	// "claude"). When set, aks uses BPF process lineage tracking: only the
	// entry process and all its descendants emit events. This eliminates false
	// positives from unrelated processes sharing the same comm (e.g. VS Code's
	// "node" vs gemini-cli's "node"). Requires kernel 5.7+.
	EntryComm string `yaml:"entry_comm"`

	// WatchedComms restricts event collection to the listed process names
	// (kernel comm, max 15 chars). Used when entry_comm is not set.
	// If both are empty, all processes are watched.
	WatchedComms []string `yaml:"watched_comms"`

	DeniedPaths     []string `yaml:"denied_paths"`
	AllowedPaths    []string `yaml:"allowed_paths"`
	AllowedNetworks []string `yaml:"allowed_networks"`
	AllowedCommands []string `yaml:"allowed_commands"`

	// v1 tool-scoped schema (SPEC §9.1). All optional so legacy yamls
	// without these keys keep loading unchanged.
	Default    string                `yaml:"default"`
	Baseline   *Baseline             `yaml:"baseline"`
	Tools      map[string]ToolPolicy `yaml:"tools"`
	Restricted *Restricted           `yaml:"restricted"`

	// compiled
	allowedNets []*net.IPNet
}

// compile parses CIDRs into net.IPNet for fast matching.
func (p *Profile) compile() error {
	p.allowedNets = nil
	for _, cidr := range p.AllowedNetworks {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q in profile %q: %w", cidr, p.Name, err)
		}
		p.allowedNets = append(p.allowedNets, ipNet)
	}
	return nil
}

// WatchComm reports whether events from a process named comm should be
// processed by the Go detector.
//
// When EntryComm is set, BPF lineage tracking has already filtered the ring
// buffer to only contain events from the agent's process tree. The Go layer
// must not re-filter by comm name, so WatchComm always returns true.
//
// When EntryComm is empty, WatchedComms applies: if the list is non-empty,
// only listed names pass; an empty list watches all processes.
func (p *Profile) WatchComm(comm string) bool {
	if p.EntryComm != "" {
		return true // BPF lineage tracking active; trust the ring buffer
	}
	if len(p.WatchedComms) == 0 {
		return true
	}
	for _, c := range p.WatchedComms {
		if c == comm {
			return true
		}
	}
	return false
}

// DefaultDeny reports whether the default policy is to deny unmatched actions.
// The v1 `default` key wins when set; otherwise legacy `default_policy`
// applies (empty still means deny: fail closed).
func (p *Profile) DefaultDeny() bool {
	if p.Default != "" {
		return p.Default != "allow"
	}
	return p.DefaultPolicy != "allow"
}

// EffectiveExec returns baseline exec + the tool's additions. Unknown tools
// get baseline only. The result never contains entries outside the YAML.
func (p *Profile) EffectiveExec(tool string) []string {
	var out []string
	if p.Baseline != nil {
		out = append(out, p.Baseline.Exec...)
	}
	if t, ok := p.Tools[tool]; ok {
		out = append(out, t.Exec...)
	}
	return out
}

// EffectiveNet returns baseline net + the tool's additions. Unknown tools
// get baseline only. The result never contains entries outside the YAML.
func (p *Profile) EffectiveNet(tool string) []string {
	var out []string
	if p.Baseline != nil {
		out = append(out, p.Baseline.Net...)
	}
	if t, ok := p.Tools[tool]; ok {
		out = append(out, t.Net...)
	}
	return out
}

// EffectiveFS returns the fs mode for a tool: the tool's fs wins, else the
// baseline fs. Unknown tools get the restricted fs (default read_only).
// deny_files always applies on top (see EffectiveDenyFiles).
func (p *Profile) EffectiveFS(tool string) string {
	if t, ok := p.Tools[tool]; ok {
		if t.Fs != "" {
			return t.Fs
		}
		if p.Baseline != nil && p.Baseline.Fs != "" {
			return p.Baseline.Fs
		}
		return ""
	}
	if tool == "" || tool == "baseline" {
		if p.Baseline != nil {
			return p.Baseline.Fs
		}
		return ""
	}
	// Unknown tool: restricted profile (baseline exec/net, fs read_only).
	if p.Restricted != nil && p.Restricted.Fs != "" {
		return p.Restricted.Fs
	}
	return "read_only"
}

// EffectiveDenyFiles returns the deny_files set, which always applies to
// every tool including unknown ones.
func (p *Profile) EffectiveDenyFiles() []string {
	if p.Baseline == nil {
		return nil
	}
	return p.Baseline.DenyFiles
}

// MatchPath returns the verdict for a file open at the given path.
// Denied patterns are checked before allowed patterns.
func (p *Profile) MatchPath(path string) Verdict {
	for _, pattern := range p.DeniedPaths {
		if globMatch(pattern, path) {
			return VerdictDeny
		}
	}
	for _, pattern := range p.AllowedPaths {
		if globMatch(pattern, path) {
			return VerdictAllow
		}
	}
	return VerdictDefault
}

// MatchIP returns the verdict for an outbound connection to ip.
func (p *Profile) MatchIP(ip net.IP) Verdict {
	for _, network := range p.allowedNets {
		if network.Contains(ip) {
			return VerdictAllow
		}
	}
	return VerdictDefault
}

// MatchCommand returns the verdict for spawning the process at cmdPath.
// Matching is done on the basename so both "ollama" and "/usr/bin/ollama" work.
// When AllowedCommands is non-empty, a basename not on the list is an explicit
// deny so the detector can block it before consulting path rules. When the
// list is empty, every command defers to the default policy.
func (p *Profile) MatchCommand(cmdPath string) Verdict {
	if len(p.AllowedCommands) == 0 {
		return VerdictDefault
	}
	base := filepath.Base(cmdPath)
	for _, allowed := range p.AllowedCommands {
		if base == allowed {
			return VerdictAllow
		}
	}
	return VerdictDeny
}

// globMatch wraps doublestar.Match with a safe fallback.
func globMatch(pattern, s string) bool {
	matched, err := doublestar.Match(pattern, s)
	if err != nil {
		return false
	}
	return matched
}
