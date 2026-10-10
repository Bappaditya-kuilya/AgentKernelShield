package profiles

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and parses a profile YAML from disk.
func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile %q: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses a profile from raw YAML bytes. Unknown keys are rejected
// (strict decode, error carries the yaml line number); legacy CIDR compile
// behavior is unchanged; v1 tool-scoped fields are validated with line+reason.
func LoadBytes(data []byte) (*Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("line 1: policy must not be empty")
		}
		return nil, fmt.Errorf("parsing profile YAML: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	if err := p.validate(data); err != nil {
		return nil, err
	}
	return &p, nil
}

// validate checks the v1 tool-scoped schema (SPEC §9.1). Files without any of
// default/baseline/tools/restricted are legacy and skip version checks so
// every existing yaml keeps loading. Every error carries line number + reason.
func (p *Profile) validate(data []byte) error {
	var doc yaml.Node
	_ = yaml.Unmarshal(data, &doc) // syntax errors already reported by strict decode
	root := rootMapping(&doc)

	if strings.TrimSpace(p.Name) == "" {
		line := mapKeyLine(root, "name")
		if line == 0 {
			line = 1
		}
		return fmt.Errorf("line %d: policy name must not be empty", line)
	}

	if len(p.EntryComm) > 15 {
		line := mapKeyLine(root, "entry_comm")
		if line == 0 {
			line = 1
		}
		return fmt.Errorf("line %d: entry_comm %q exceeds 15 char kernel comm limit (TASK_COMM_LEN)", line, p.EntryComm)
	}

	hasNew := p.Default != "" || p.Baseline != nil || len(p.Tools) > 0 || p.Restricted != nil
	if !hasNew {
		return nil
	}

	if string(p.Version) != "1" {
		line := mapKeyLine(root, "version")
		if line == 0 {
			line = 1
		}
		return fmt.Errorf("line %d: policy version must be 1, got %q", line, string(p.Version))
	}

	if p.Default != "" && p.Default != "deny" && p.Default != "allow" {
		line := mapKeyLine(root, "default")
		if line == 0 {
			line = 1
		}
		return fmt.Errorf("line %d: invalid default value %q: must be \"deny\" or \"allow\"", line, p.Default)
	}

	if p.Baseline != nil {
		bNode := mapValue(root, "baseline")
		if err := validateFSValue(p.Baseline.Fs, bNode, "baseline", ""); err != nil {
			return err
		}
		netNode := mapValue(bNode, "net")
		for i, e := range p.Baseline.Net {
			if err := checkHostPort(e); err != nil {
				line := seqItemLine(netNode, i)
				if line == 0 {
					line = mapKeyLine(bNode, "net")
				}
				if line == 0 {
					line = 1
				}
				return fmt.Errorf("line %d: invalid net entry %q in baseline.net: %s", line, e, err)
			}
		}
		execNode := mapValue(bNode, "exec")
		for i, e := range p.Baseline.Exec {
			if strings.TrimSpace(e) == "" {
				line := seqItemLine(execNode, i)
				if line == 0 {
					line = 1
				}
				return fmt.Errorf("line %d: baseline.exec entry %d must not be empty", line, i)
			}
		}
		denyNode := mapValue(bNode, "deny_files")
		for i, e := range p.Baseline.DenyFiles {
			if strings.TrimSpace(e) == "" {
				line := seqItemLine(denyNode, i)
				if line == 0 {
					line = 1
				}
				return fmt.Errorf("line %d: baseline.deny_files entry %d must not be empty", line, i)
			}
		}
	}

	if len(p.Tools) > 0 {
		toolsNode := mapValue(root, "tools")
		for name, tp := range p.Tools {
			if strings.TrimSpace(name) == "" {
				line := 0
				if toolsNode != nil {
					line = toolsNode.Line
				}
				if line == 0 {
					line = 1
				}
				return fmt.Errorf("line %d: tool name must not be empty", line)
			}
			tNode := mapValue(toolsNode, name)
			if err := validateFSValue(tp.Fs, tNode, "tool", name); err != nil {
				return err
			}
			netNode := mapValue(tNode, "net")
			for i, e := range tp.Net {
				if err := checkHostPort(e); err != nil {
					line := seqItemLine(netNode, i)
					if line == 0 {
						line = mapKeyLine(tNode, "net")
					}
					if line == 0 {
						line = 1
					}
					return fmt.Errorf("line %d: invalid net entry %q in tool %q: %s", line, e, name, err)
				}
			}
			execNode := mapValue(tNode, "exec")
			for i, e := range tp.Exec {
				if strings.TrimSpace(e) == "" {
					line := seqItemLine(execNode, i)
					if line == 0 {
						line = 1
					}
					return fmt.Errorf("line %d: tool %q exec entry %d must not be empty", line, name, i)
				}
			}
		}
	}

	if p.Restricted != nil {
		rNode := mapValue(root, "restricted")
		if err := validateFSValue(p.Restricted.Fs, rNode, "restricted", ""); err != nil {
			return err
		}
	}

	return nil
}

// validateFSValue rejects fs strings outside {read_write, read_only}.
// Empty (absent) is allowed and means "inherit / unset".
func validateFSValue(fs string, scopeNode *yaml.Node, scope, tool string) error {
	if fs == "" || fs == "read_write" || fs == "read_only" {
		return nil
	}
	line := 0
	if scopeNode != nil {
		line = mapKeyLine(scopeNode, "fs")
		if line == 0 {
			line = scopeNode.Line
		}
	}
	if line == 0 {
		line = 1
	}
	if scope == "tool" {
		return fmt.Errorf("line %d: invalid fs value %q in tool %q: must be \"read_write\" or \"read_only\"", line, fs, tool)
	}
	return fmt.Errorf("line %d: invalid fs value %q in %s: must be \"read_write\" or \"read_only\"", line, fs, scope)
}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// checkHostPort validates "host:port" entries (SPEC §9.1 baseline/tools net).
func checkHostPort(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	if strings.ContainsAny(s, " \t\n/") {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	host, portStr := s[:i], s[i+1:]
	if host == "" || portStr == "" {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return fmt.Errorf("must be \"host:port\" with port 1-65535")
		}
		if net.ParseIP(host[1:len(host)-1]) == nil {
			return fmt.Errorf("must be \"host:port\" with port 1-65535")
		}
		return nil
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("IPv6 must use brackets like \"[::1]:443\"")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	if !hostnameRe.MatchString(host) {
		return fmt.Errorf("must be \"host:port\" with port 1-65535")
	}
	return nil
}

// rootMapping unwraps a decoded document to its root mapping, or nil.
func rootMapping(doc *yaml.Node) *yaml.Node {
	n := doc
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapKeyLine returns the line of key in a mapping node, or 0.
func mapKeyLine(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return 0
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i].Line
		}
	}
	return 0
}

// seqItemLine returns the line of the idx-th sequence item, or 0.
func seqItemLine(seq *yaml.Node, idx int) int {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return 0
	}
	if idx >= 0 && idx < len(seq.Content) {
		return seq.Content[idx].Line
	}
	return seq.Line
}
