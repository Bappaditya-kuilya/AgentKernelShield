//go:build linux

// bypass_target is the synthetic "evasive rogue process" for the bypass suite.
// It attempts exec/file vectors that try to dodge exact-path enforcement:
// shebang indirection, symlink indirection, execveat, interpreter -c flags,
// and a fork-storm that stresses lineage propagation.
//
// Exit codes:
//   0 — every vector was blocked (aks worked correctly)
//   1 — at least one vector succeeded (aks failed to block)
//
// Omitted by design (see plan.md Phase 7): hardlink and memfd+fexecve
// (invisible to exact-path maps — need the (dev,ino) redesign), unix-socket
// connect (allowed for non-IP families by design), io_uring (VM follow-up).

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe" // test-only: argv pointer arrays for the raw execveat trap

	"golang.org/x/sys/unix"
)

func main() {
	// Child mode for the fork-storm: attempt one blocked open, report via exit code.
	if len(os.Args) > 1 && os.Args[1] == "-fork-child" {
		if tryFileRead("/etc/shadow") {
			os.Exit(1) // allowed — aks missed
		}
		os.Exit(0) // blocked
	}

	results := run()
	allBlocked := true
	for _, r := range results {
		status := "BLOCKED ✓"
		if r.allowed {
			status = "ALLOWED  ✗ (aks missed this!)"
			allBlocked = false
		}
		fmt.Printf("%-50s %s\n", r.name, status)
	}
	if !allBlocked {
		os.Exit(1)
	}

	// ── Bypass 5: execveat (runs last — replaces the image on success) ──
	// Blocked → EPERM error, fall through to exit 0. Allowed → image
	// becomes bash, which exits 3 (unambiguous "missed", never 0 or 1).
	tryExecveatLast()
	fmt.Printf("%-50s %s\n", "execveat(/bin/bash)", "BLOCKED ✓")
}

// execveatTrap returns the execveat syscall number for known arches.
// x/sys here has no Execveat wrapper and stdlib exposes no AT_FDCWD, so the
// raw trap + UAPI constants are used (stdlib only, no new deps).
// AT_FDCWD is -100 on every Linux arch.
const atFDCWD = -100

func execveatTrap() (uintptr, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return 322, true // __NR_execveat, arch/x86
	case "arm64":
		return 281, true // __NR_execveat, arm64
	default:
		return 0, false
	}
}

// dfdUuintptr converts atFDCWD (-100) for the trap argument via a variable
// so the wrapping conversion happens at runtime (constant -100 overflows
// uintptr at compile time).
func dfdUuintptr() uintptr {
	dfd := int32(atFDCWD)
	return uintptr(dfd)
}

// never returns on success. On EPERM/EACCES it returns (blocked); on any
// other outcome it exits 1 (missed). Unknown arch prints SKIPPED.
// tryExecveatLast invokes execveat(AT_FDCWD, /bin/bash -c "exit 3") and
// never returns on success. On EPERM/EACCES it returns (blocked); on any
// other outcome it exits 1 (missed). Unknown arch prints SKIPPED.
func tryExecveatLast() {
	trap, ok := execveatTrap()
	if !ok {
		fmt.Printf("%-50s %s (arch %s)\n", "execveat(/bin/bash)", "SKIPPED ✓", runtime.GOARCH)
		return
	}
	path, _ := unix.BytePtrFromString("/bin/bash")
	a0, _ := unix.BytePtrFromString("bash")
	a1, _ := unix.BytePtrFromString("-c")
	a2, _ := unix.BytePtrFromString("exit 3")
	argv := []uintptr{
		uintptr(unsafe.Pointer(a0)),
		uintptr(unsafe.Pointer(a1)),
		uintptr(unsafe.Pointer(a2)),
		0,
	}
	_, _, errno := unix.Syscall6(trap,
		dfdUuintptr(),
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&argv[0])),
		0, 0, 0)
	if errno == syscall.EPERM || errno == syscall.EACCES {
		return // blocked
	}
	// Success replaces the image (bash exits 3); any other error is a miss.
	fmt.Printf("%-50s %s (%v)\n", "execveat(/bin/bash)", "ALLOWED  ✗ (aks missed this!)", errno)
	os.Exit(1)
}

type result struct {
	name    string
	allowed bool
}

func run() []result {
	return []result{
		// ── Bypass 1: shebang indirection ───────────────────────────────
		// Script cats /etc/shadow via an interpreter. Block lands either
		// on the interpreter exec (/usr/bin/sh denied) or the file open.
		{
			name:    "shebang script → /etc/shadow",
			allowed: tryShebangCat(),
		},
		// ── Bypass 2: symlink indirection ───────────────────────────────
		// d_path resolves the link, so the open hits /etc/shadow.
		{
			name:    "symlink → /etc/shadow",
			allowed: trySymlinkRead(),
		},
		// ── Bypass 3: interpreter -c flags ──────────────────────────────
		{
			name:    "execve(/usr/bin/python3 -c)",
			allowed: tryExecArgs("/usr/bin/python3", "-c", "x=1"),
		},
		{
			name:    "execve(/bin/bash -c)",
			allowed: tryExecArgs("/bin/bash", "-c", "echo hi"),
		},
		// ── Bypass 4: fork-storm lineage stress ─────────────────────────
		// 32 children of the watched tree each open /etc/shadow. Every
		// child must be attributed and blocked.
		{
			name:    "fork-storm 32× open(/etc/shadow)",
			allowed: tryForkStorm(32),
		},
		// NOTE: Bypass 5 (execveat) runs after the table in main() — it
		// replaces the process image on success and cannot return.
	}
}

func tryShebangCat() (allowed bool) {
	script := filepath.Join(os.TempDir(), fmt.Sprintf("bypass_shebang_%d.sh", os.Getpid()))
	content := "#!/bin/sh\ncat /etc/shadow\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		return true // inconclusive — fail toward "missed"
	}
	defer os.Remove(script)
	cmd := exec.Command(script)
	err := cmd.Run()
	if err == nil {
		return true
	}
	return !isPermError(err)
}

func trySymlinkRead() (allowed bool) {
	link := filepath.Join(os.TempDir(), fmt.Sprintf("bypass_link_%d", os.Getpid()))
	if err := os.Symlink("/etc/shadow", link); err != nil {
		return true // inconclusive — fail toward "missed"
	}
	defer os.Remove(link)
	return tryFileRead(link)
}

func tryExecArgs(path string, args ...string) (allowed bool) {
	cmd := exec.Command(path, args...)
	err := cmd.Run()
	if err == nil {
		return true
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			// EPERM propagates as exit status 126 or the raw signal
			if status.ExitStatus() == 126 {
				return false
			}
		}
	}
	return !isPermError(err)
}

func tryForkStorm(n int) (allowed bool) {
	self, err := os.Executable()
	if err != nil {
		return true // inconclusive — fail toward "missed"
	}
	type childRes struct{ allowed bool }
	results := make(chan childRes, n)
	for i := 0; i < n; i++ {
		go func() {
			cmd := exec.Command(self, "-fork-child")
			if err := cmd.Run(); err != nil {
				results <- childRes{allowed: true}
				return
			}
			// Exit 0 from the child means blocked; anything else means missed.
			// cmd.Run() returns nil only on exit 0.
			results <- childRes{allowed: false}
		}()
	}
	anyAllowed := false
	for i := 0; i < n; i++ {
		if r := <-results; r.allowed {
			anyAllowed = true
		}
	}
	return anyAllowed
}

func tryFileRead(path string) (allowed bool) {
	_, err := os.Open(path)
	if err == nil {
		return true // succeeded — aks didn't block
	}
	return !isPermError(err)
}

func isPermError(err error) bool {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err == syscall.EPERM || pathErr.Err == syscall.EACCES
	}
	return false
}
