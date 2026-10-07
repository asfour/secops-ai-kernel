package server

import (
	"crypto/sha256"
	"fmt"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/sandbox/firecracker"
)

// ForkVerifyServer implements pb.ForkVerifyEngineServer. It redeems a
// simulation_token minted by CompilerServer.CompileZKIntent, replays the
// compiled intent inside an isolated Firecracker microVM, and streams back
// the resulting verdict.
type ForkVerifyServer struct {
	pb.UnimplementedForkVerifyEngineServer

	compiler     *CompilerServer
	orchestrator *firecracker.Orchestrator

	// KernelPath / RootfsPath point at the guest boot images every
	// microVM replay uses. Real per-request guest state injection
	// (cloning the actual target resource under test into the rootfs)
	// is not implemented — see IMPROVEMENT_SPEC.md item #6.
	KernelPath string
	RootfsPath string

	// MemoryLimitMB is the default microVM memory limit, sourced from
	// configs/secops-kernel.yaml's engine.memory_fence_bytes. Previously
	// this was a hardcoded 512 with no connection to that config file at
	// all.
	MemoryLimitMB int64
}

func NewForkVerifyServer(compiler *CompilerServer, orchestrator *firecracker.Orchestrator, kernelPath, rootfsPath string, memoryLimitMB int64) *ForkVerifyServer {
	return &ForkVerifyServer{
		compiler:      compiler,
		orchestrator:  orchestrator,
		KernelPath:    kernelPath,
		RootfsPath:    rootfsPath,
		MemoryLimitMB: memoryLimitMB,
	}
}

func (s *ForkVerifyServer) ExecuteForkVerify(req *pb.ForkVerifyRequest, stream pb.ForkVerifyEngine_ExecuteForkVerifyServer) error {
	pending, ok := s.compiler.takePending(req.GetSimulationToken())
	if !ok {
		return stream.Send(&pb.ForkVerifyResponse{
			Verdict: pb.ExecutionVerdict_VERDICT_0x00_ABORT,
		})
	}

	microvmID := req.GetSimulationToken()
	cfg := &firecracker.MicroVMConfig{
		ID:            microvmID,
		KernelPath:    s.KernelPath,
		RootfsPath:    s.RootfsPath,
		SocketPath:    fmt.Sprintf("/tmp/%s.sock", microvmID),
		MemoryLimitMB: s.MemoryLimitMB,
		CPUTimeoutMs:  pending.maxLatency,
	}

	ctx := stream.Context()
	_, diff, err := s.orchestrator.SpawnAndMeasure(ctx, cfg)
	if err != nil {
		return stream.Send(&pb.ForkVerifyResponse{
			MicrovmId: microvmID,
			Verdict:   pb.ExecutionVerdict_VERDICT_0x00_ABORT,
		})
	}

	// MemoryDriftBytes and FilesMutated above are both real observations
	// (see firecracker.MeasuredDiff). NetworkPacketsDropped is not
	// measured — the orchestrator never configures a network interface
	// for the guest at all. See IMPROVEMENT_SPEC.md item #9.
	commitHash := sha256.Sum256([]byte(microvmID + pending.agentID))

	return stream.Send(&pb.ForkVerifyResponse{
		MicrovmId: microvmID,
		DiffMetrics: &pb.StateDiffMetrics{
			MemoryDriftBytes: diff.MemoryDriftBytes,
			FilesMutated:     diff.FilesMutated,
		},
		Verdict:         pb.ExecutionVerdict_VERDICT_0x01_PASS,
		CommitReadyHash: commitHash[:],
	})
}
