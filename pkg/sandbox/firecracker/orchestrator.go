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

	// VCPUCount defaults to 1 if unset. BootArgs is passed through to
	// Firecracker's /boot-source as-is.
	VCPUCount int64
	BootArgs  string

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
// IMPROVEMENT_SPEC.md item #3) — including the very firecracker
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

// SpawnAndMeasure boots a Firecracker guest from cfg via SpawnIsolatedStateMirror,
// configures it over the Firecracker REST API, and returns a real byte-level
// memory diff between a snapshot taken just after boot and one taken partway
// through the execution window — replacing the previous placeholder, which
// hashed the *request* and never observed anything the guest actually did
// (IMPROVEMENT_SPEC.md item #6).
//
// FilesMutated and NetworkPacketsDropped are not measured here: they would
// require a rootfs overlay diff and a network-namespace packet counter
// respectively, neither of which this orchestrator sets up. Callers must
// not treat their absence as "zero changes" — only MemoryDriftBytes is a
// real observation.
//
// The post-execution snapshot is deliberately taken at half of
// cfg.CPUTimeoutMs, not at the full timeout: SpawnIsolatedStateMirror's own
// background goroutine kills the process and removes cfg.SocketPath at the
// full timeout, which would otherwise race this method's final API calls.
func (o *Orchestrator) SpawnAndMeasure(ctx context.Context, cfg *MicroVMConfig) (microvmID string, memoryDriftBytes uint64, err error) {
	if _, err := o.SpawnIsolatedStateMirror(ctx, cfg); err != nil {
		return "", 0, err
	}

	if err := waitForSocket(ctx, cfg.SocketPath, 2*time.Second); err != nil {
		return cfg.ID, 0, fmt.Errorf("waiting for firecracker api socket: %w", err)
	}

	api := NewAPIClient(cfg.SocketPath)
	vcpuCount := cfg.VCPUCount
	if vcpuCount <= 0 {
		vcpuCount = 1
	}

	if err := api.ConfigureMachine(ctx, vcpuCount, cfg.MemoryLimitMB); err != nil {
		return cfg.ID, 0, err
	}
	if err := api.ConfigureBootSource(ctx, cfg.KernelPath, cfg.BootArgs); err != nil {
		return cfg.ID, 0, err
	}
	if err := api.ConfigureRootDrive(ctx, "rootfs", cfg.RootfsPath); err != nil {
		return cfg.ID, 0, err
	}
	if err := api.StartInstance(ctx); err != nil {
		return cfg.ID, 0, err
	}

	preMemPath := cfg.SocketPath + ".pre.mem"
	if err := snapshotPaused(ctx, api, cfg.SocketPath+".pre.json", preMemPath); err != nil {
		return cfg.ID, 0, err
	}

	select {
	case <-time.After(cfg.CPUTimeoutMs / 2):
	case <-ctx.Done():
	}

	postMemPath := cfg.SocketPath + ".post.mem"
	if err := snapshotPaused(ctx, api, cfg.SocketPath+".post.json", postMemPath); err != nil {
		return cfg.ID, 0, err
	}

	drift, err := diffFiles(preMemPath, postMemPath)
	if err != nil {
		return cfg.ID, 0, fmt.Errorf("diffing guest memory snapshots: %w", err)
	}

	return cfg.ID, drift, nil
}

func snapshotPaused(ctx context.Context, api *APIClient, snapshotPath, memFilePath string) error {
	if err := api.PauseVM(ctx); err != nil {
		return fmt.Errorf("pausing guest for snapshot: %w", err)
	}
	if err := api.CreateSnapshot(ctx, snapshotPath, memFilePath); err != nil {
		return fmt.Errorf("creating guest snapshot: %w", err)
	}
	if err := api.ResumeVM(ctx); err != nil {
		return fmt.Errorf("resuming guest after snapshot: %w", err)
	}
	return nil
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for %q to appear", path)
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
