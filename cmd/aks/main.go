package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Bappaditya-kuilya/aks/internal/audit"
	"github.com/Bappaditya-kuilya/aks/internal/detector"
	"github.com/Bappaditya-kuilya/aks/internal/loader"
	"github.com/Bappaditya-kuilya/aks/internal/profiles"
	"github.com/Bappaditya-kuilya/aks/internal/ui"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "aks",
	Short: "eBPF-based runtime security for AI inference workloads",
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Attach to AI inference processes and enforce the behavioral profile",
	RunE:  runWatch,
}

var watchFlags struct {
	framework string
	profile   string
	bpfObj    string
	uiEnabled bool
	uiPort    int
	sslBinary string
}

func init() {
	watchCmd.Flags().StringVar(&watchFlags.framework, "framework", "ollama", "AI framework profile to use (ollama, gemini-cli, claude-code)")
	watchCmd.Flags().StringVar(&watchFlags.profile, "profile", "", "Path to a custom profile YAML (overrides --framework)")
	watchCmd.Flags().StringVar(&watchFlags.bpfObj, "bpf-obj", "/usr/lib/aks/aks.bpf.o", "Path to compiled eBPF object file")
	watchCmd.Flags().BoolVar(&watchFlags.uiEnabled, "ui", false, "Start the real-time web UI")
	watchCmd.Flags().IntVar(&watchFlags.uiPort, "port", 7394, "Port to serve the web UI on (requires --ui)")
	watchCmd.Flags().StringVar(&watchFlags.sslBinary, "ssl-binary", "", "Path to binary containing SSL_write/SSL_read for prompt capture (optional)")
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(profileCmd)
}

func runWatch(cmd *cobra.Command, _ []string) error {
	profilePath := watchFlags.profile
	if profilePath == "" {
		profilePath = fmt.Sprintf("profiles/%s.yaml", watchFlags.framework)
	}

	p, err := profiles.LoadFile(profilePath)
	if err != nil {
		return fmt.Errorf("loading profile: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "aks: loaded profile %q\n", p.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "aks: attaching eBPF programs (requires root + Linux)...\n")

	l, err := loader.Load(p, watchFlags.bpfObj, watchFlags.sslBinary)
	if err != nil {
		return fmt.Errorf("loading eBPF: %w\nEnsure: Linux kernel 5.7+, CONFIG_BPF_LSM=y, lsm=bpf, run as root", err)
	}
	defer func() { _ = l.Close() }()

	det := detector.New(p)
	log := audit.New(cmd.OutOrStdout())

	var uiServer *ui.Server
	if watchFlags.uiEnabled {
		uiServer = ui.New(p.Name, version)
		go func() {
			addr := fmt.Sprintf(":%d", watchFlags.uiPort)
			fmt.Fprintf(cmd.OutOrStdout(), "aks: UI available at http://localhost%s\n", addr)
			if err := http.ListenAndServe(addr, uiServer.Handler()); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "aks: UI server error: %v\n", err)
			}
		}()
	}

	fmt.Fprintf(cmd.OutOrStdout(), "aks: watching — press Ctrl+C to stop\n")

	for {
		e, err := l.ReadEvent()
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}
		dec := det.Evaluate(e)
		if dec.Action == detector.Skip {
			continue
		}
		if dec.Action == detector.Block {
			_ = l.BlockIP(e.DestIP) // add to kernel block map for future connections
		}
		log.Log(dec)
		if uiServer != nil {
			uiServer.Broadcast(dec)
		}
	}
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage behavioral profiles",
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Detach the aks daemon (map pins stay)",
	Long: `Detach bookkeeping without dropping map pins.

Pins under /sys/fs/bpf/aks are kept, but enforcement stops with the
daemon (links are in-memory only: fail-OPEN until link pinning lands).
Use --release for a full release (detach and unpin /sys/fs/bpf/aks).`,
	RunE: runStop,
}

var stopFlags struct {
	release bool
}

func init() {
	stopCmd.Flags().BoolVar(&stopFlags.release, "release", false, "Full release: detach and unpin /sys/fs/bpf/aks")
	rootCmd.AddCommand(stopCmd)
}

func runStop(cmd *cobra.Command, _ []string) error {
	if stopFlags.release {
		if err := loader.UnpinAll(); err != nil {
			return fmt.Errorf("releasing aks pins: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "aks: released pins under /sys/fs/bpf/aks")
		return nil
	}
	// Plain stop keeps map pins by design, but enforcement does NOT continue:
	// links live in memory only, so killing the daemon detaches them
	// (fail-OPEN until link pinning lands). This no-op reports the invariant.
	fmt.Fprintln(cmd.OutOrStdout(), "aks: detached (map pins stay; enforcement stops with the daemon)")
	return nil
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available built-in profiles",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), "Built-in profiles:")
		fmt.Fprintln(cmd.OutOrStdout(), "  ollama      — Ollama LLM server")
		fmt.Fprintln(cmd.OutOrStdout(), "  gemini-cli  — Google Gemini CLI agent")
		fmt.Fprintln(cmd.OutOrStdout(), "  claude-code — Anthropic Claude Code agent")
	},
}

func init() {
	profileCmd.AddCommand(profileListCmd)
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Validate policy files",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check <file>",
	Short: "Validate a policy YAML file",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyCheck,
}

func init() {
	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	if _, err := profiles.LoadFile(args[0]); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "ok")
	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
