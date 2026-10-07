package firecracker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

type MicroVMConfig struct {
	ID            string
	KernelPath    string
	RootfsPath    string
	SocketPath    string
	MemoryLimitMB int64
	CPUTimeoutMs  time.Duration

	// AgentID / PermissionMask are forwarded to the eBPF token grant for
	// this microVM's host process, so monitor.c's token_metadata carries
	// the same identity the gRPC caller authenticated with.
	AgentID        uint64
	PermissionMask uint32
}

// TokenGranter is satisfied by *ebpftoken.Controller. It is an interface
// here (rather than a direct dependency) so this package stays buildable
// and testable without requiring a loaded BPF object.
type TokenGranter interface {
	Grant(pid uint32, agentID uint64, permissionMask uint32, ttl time.Duration) error
	Revoke(pid uint32) error
}

type Orchestrator struct {
	ActiveVMs map[string]*MicroVMConfig
	Tokens    TokenGranter // nil disables eBPF enforcement (dev/test only)
}

func NewOrchestrator(tokens TokenGranter) *Orchestrator {
	return &Orchestrator{
		ActiveVMs: make(map[string]*MicroVMConfig),
		Tokens:    tokens,
	}
}

// SpawnIsolatedStateMirror starts an isolated firecracker process for cfg
// and, if a TokenGranter is configured, grants that process an eBPF
// execution token *before* it is allowed to run past its own exec() call.
//
// Without this, pkg/kernel/ebpf/monitor.c's sys_enter_execve hook has no
// record of the process and will SIGKILL it immediately (see
// docs/improvement_spec.md item #3) — including the very firecracker
// binary this orchestrator is trying to run.
//
// To close the race between "process exists" and "token is granted", the
// child is started under PTRACE_TRACEME. The kernel guarantees a traced
// process stops with SIGTRAP immediately after its own execve() call
// completes and before the new program's first instruction runs. We use
// that guaranteed stop to grant the token, then PTRACE_DETACH to resume
// normal, untraced execution.
func (o *Orchestrator) SpawnIsolatedStateMirror(ctx context.Context, cfg *MicroVMConfig) (string, error) {
	if _, err := os.Stat(cfg.KernelPath); os.IsNotExist(err) {
		return "", fmt.Errorf("kernel boot binary target error: %w", err)
	}

	cmd := exec.CommandContext(ctx, "firecracker", "--api-sock", cfg.SocketPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
		Ptrace:    o.Tokens != nil,
	}

	if o.Tokens != nil {
		// Wait4/PTRACE_* calls are only valid from the thread that owns
		// the traced child; exec.Cmd.Start() forks from the calling
		// goroutine's thread, so we must pin it for the handshake below.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to drop process into microvm jailer execution: %w", err)
	}
	pid := cmd.Process.Pid

	if o.Tokens != nil {
		if err := o.waitForExecStopAndGrantToken(cfg, pid); err != nil {
			_ = cmd.Process.Kill()
			return "", err
		}
	}

	o.ActiveVMs[cfg.ID] = cfg

	go func() {
		time.Sleep(cfg.CPUTimeoutMs)
		_ = cmd.Process.Kill()
		if o.Tokens != nil {
			_ = o.Tokens.Revoke(uint32(pid))
		}
		_ = os.Remove(cfg.SocketPath)
	}()

	return cfg.ID, nil
}

func (o *Orchestrator) waitForExecStopAndGrantToken(cfg *MicroVMConfig, pid int) error {
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return fmt.Errorf("waiting for traced exec stop (pid %d): %w", pid, err)
	}
	if !status.Stopped() || status.StopSignal() != syscall.SIGTRAP {
		return fmt.Errorf("pid %d did not stop at exec as expected (status=%v)", pid, status)
	}

	if err := o.Tokens.Grant(uint32(pid), cfg.AgentID, cfg.PermissionMask, cfg.CPUTimeoutMs); err != nil {
		return fmt.Errorf("granting eBPF token to pid %d: %w", pid, err)
	}

	if err := syscall.PtraceDetach(pid); err != nil {
		return fmt.Errorf("detaching ptrace from pid %d: %w", pid, err)
	}
	return nil
}
