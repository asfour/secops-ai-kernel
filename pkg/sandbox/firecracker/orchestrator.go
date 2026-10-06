package firecracker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type MicroVMConfig struct {
	ID             string
	KernelPath     string
	RootfsPath     string
	SocketPath     string
	MemoryLimitMB  int64
	CPUTimeoutMs   time.Duration
}

type Orchestrator struct {
	ActiveVMs map[string]*MicroVMConfig
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		ActiveVMs: make(map[string]*MicroVMConfig),
	}
}

func (o *Orchestrator) SpawnIsolatedStateMirror(ctx context.Context, cfg *MicroVMConfig) (string, error) {
	if _, err := os.Stat(cfg.KernelPath); os.IsNotExist(err) {
		return "", fmt.Errorf("kernel boot binary target error: %w", err)
	}

	cmd := exec.CommandContext(ctx, "firecracker", "--api-sock", cfg.SocketPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	err := cmd.Start()
	if err != nil {
		return "", fmt.Errorf("failed to drop process into microvm jailer execution: %w", err)
	}

	o.ActiveVMs[cfg.ID] = cfg

	go func() {
		time.Sleep(cfg.CPUTimeoutMs)
		_ = cmd.Process.Kill()
		_ = os.Remove(cfg.SocketPath)
	}()

	return cfg.ID, nil
}
