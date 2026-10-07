package firecracker

import (
	"context"
	"fmt"
	"io"
	"log"
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

	// AllowedSubnet is the validated subnet number (pkg/server.ExtractSubnet,
	// [1000,9999]) the guest's network traffic is scoped to. Zero means
	// "no network interface at all" — SpawnAndMeasure skips network
	// fencing entirely rather than giving the guest an unscoped interface.
	AllowedSubnet int

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

	// EnforceNetworkFence controls what happens when cfg.AllowedSubnet > 0
	// but SetupNetworkFence fails (e.g. missing CAP_NET_ADMIN): if true,
	// SpawnAndMeasure aborts; if false (the zero value — dev/test only,
	// mirroring Tokens==nil), it logs and proceeds with no network
	// interface and NetworkPacketsDropped left at 0 (unmeasured, not "no
	// drops observed").
	EnforceNetworkFence bool
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

// MeasuredDiff is what SpawnAndMeasure observed about a guest's execution.
// All three fields are real observations when AllowedSubnet > 0 and
// network fencing is enforced — see each field's doc comment.
type MeasuredDiff struct {
	// MemoryDriftBytes is a byte-level diff between a guest memory
	// snapshot taken just after boot and one taken partway through the
	// execution window.
	MemoryDriftBytes uint64

	// FilesMutated counts regular files added, removed, or changed
	// (differing inode or size) between a copy of cfg.RootfsPath taken
	// just after boot and one taken partway through the execution
	// window, read directly from the ext4 image via debugfs — no
	// loopback mount or root required. See rootfsdiff.go.
	FilesMutated uint64

	// NetworkPacketsDropped counts packets the guest tried to send
	// outside cfg.AllowedSubnet, via a default-deny nftables policy on
	// a tap device scoped to that subnet — a real zero-trust enforcement
	// signal, not passive telemetry. Zero if cfg.AllowedSubnet was 0
	// (no network interface configured at all) or if network fencing
	// failed and EnforceNetworkFence is false (unmeasured, not "no
	// drops observed" — see IMPROVEMENT_SPEC.md item #15). See network.go.
	NetworkPacketsDropped uint64
}

// SpawnAndMeasure boots a Firecracker guest from cfg via SpawnIsolatedStateMirror,
// configures it over the Firecracker REST API, and returns a real
// MeasuredDiff — replacing the previous placeholder, which hashed the
// *request* and never observed anything the guest actually did
// (IMPROVEMENT_SPEC.md item #6).
//
// Both the memory and rootfs snapshots are taken while the guest is
// paused (api.PauseVM), so no further guest writes can occur between
// taking the "pre" snapshot and resuming — the rootfs copy is exactly as
// consistent as the memory snapshot it's taken alongside.
//
// The post-execution snapshot is deliberately taken at half of
// cfg.CPUTimeoutMs, not at the full timeout: SpawnIsolatedStateMirror's own
// background goroutine kills the process and removes cfg.SocketPath at the
// full timeout, which would otherwise race this method's final API calls.
func (o *Orchestrator) SpawnAndMeasure(ctx context.Context, cfg *MicroVMConfig) (microvmID string, diff MeasuredDiff, err error) {
	if _, err := o.SpawnIsolatedStateMirror(ctx, cfg); err != nil {
		return "", MeasuredDiff{}, err
	}

	if err := waitForSocket(ctx, cfg.SocketPath, 2*time.Second); err != nil {
		return cfg.ID, MeasuredDiff{}, fmt.Errorf("waiting for firecracker api socket: %w", err)
	}

	api := NewAPIClient(cfg.SocketPath)
	vcpuCount := cfg.VCPUCount
	if vcpuCount <= 0 {
		vcpuCount = 1
	}

	if err := api.ConfigureMachine(ctx, vcpuCount, cfg.MemoryLimitMB); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}
	if err := api.ConfigureBootSource(ctx, cfg.KernelPath, cfg.BootArgs); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}
	if err := api.ConfigureRootDrive(ctx, "rootfs", cfg.RootfsPath); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}

	// Network fencing must be wired up before StartInstance: the tap
	// device has to exist before Firecracker's /network-interfaces call
	// can attach to it, and that call itself must happen pre-boot (same
	// as boot-source/drives above).
	var fence *NetworkFence
	if cfg.AllowedSubnet > 0 {
		f, ferr := SetupNetworkFence(cfg.ID, cfg.AllowedSubnet)
		if ferr != nil {
			if o.EnforceNetworkFence {
				return cfg.ID, MeasuredDiff{}, fmt.Errorf("setting up network fence: %w", ferr)
			}
			log.Printf("WARNING: network fence setup failed, proceeding WITHOUT network enforcement: %v", ferr)
		} else {
			fence = f
			defer func() {
				if tdErr := fence.Teardown(); tdErr != nil {
					log.Printf("WARNING: tearing down network fence for %s: %v", cfg.ID, tdErr)
				}
			}()
			if err := api.ConfigureNetworkInterface(ctx, networkIfaceID, fence.TapName); err != nil {
				return cfg.ID, MeasuredDiff{}, fmt.Errorf("configuring guest network interface: %w", err)
			}
		}
	}

	if err := api.StartInstance(ctx); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}

	preMemPath := cfg.SocketPath + ".pre.mem"
	preRootfsPath := cfg.SocketPath + ".pre.rootfs.img"
	if err := snapshotPaused(ctx, api, cfg.SocketPath+".pre.json", preMemPath, cfg.RootfsPath, preRootfsPath); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}
	var preDrops uint64
	if fence != nil {
		if preDrops, err = fence.CountDropped(); err != nil {
			return cfg.ID, MeasuredDiff{}, fmt.Errorf("reading pre-execution drop counter: %w", err)
		}
	}

	select {
	case <-time.After(cfg.CPUTimeoutMs / 2):
	case <-ctx.Done():
	}

	postMemPath := cfg.SocketPath + ".post.mem"
	postRootfsPath := cfg.SocketPath + ".post.rootfs.img"
	if err := snapshotPaused(ctx, api, cfg.SocketPath+".post.json", postMemPath, cfg.RootfsPath, postRootfsPath); err != nil {
		return cfg.ID, MeasuredDiff{}, err
	}
	var postDrops uint64
	if fence != nil {
		if postDrops, err = fence.CountDropped(); err != nil {
			return cfg.ID, MeasuredDiff{}, fmt.Errorf("reading post-execution drop counter: %w", err)
		}
	}

	memDrift, err := diffFiles(preMemPath, postMemPath)
	if err != nil {
		return cfg.ID, MeasuredDiff{}, fmt.Errorf("diffing guest memory snapshots: %w", err)
	}

	filesMutated, err := countMutatedFiles(preRootfsPath, postRootfsPath)
	if err != nil {
		return cfg.ID, MeasuredDiff{}, fmt.Errorf("diffing guest rootfs snapshots: %w", err)
	}

	return cfg.ID, MeasuredDiff{
		MemoryDriftBytes:      memDrift,
		FilesMutated:          filesMutated,
		NetworkPacketsDropped: postDrops - preDrops,
	}, nil
}

// networkIfaceID is the fixed Firecracker network-interface ID every
// guest's single tap device is registered under.
const networkIfaceID = "eth0"

// snapshotPaused pauses the guest, takes a memory snapshot and a copy of
// its rootfs image (both safe to do only while paused, since no further
// guest writes can occur), then resumes.
func snapshotPaused(ctx context.Context, api *APIClient, snapshotPath, memFilePath, rootfsPath, rootfsCopyPath string) error {
	if err := api.PauseVM(ctx); err != nil {
		return fmt.Errorf("pausing guest for snapshot: %w", err)
	}
	if err := api.CreateSnapshot(ctx, snapshotPath, memFilePath); err != nil {
		return fmt.Errorf("creating guest snapshot: %w", err)
	}
	if err := copyFile(rootfsPath, rootfsCopyPath); err != nil {
		return fmt.Errorf("copying rootfs image while paused: %w", err)
	}
	if err := api.ResumeVM(ctx); err != nil {
		return fmt.Errorf("resuming guest after snapshot: %w", err)
	}
	return nil
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
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
