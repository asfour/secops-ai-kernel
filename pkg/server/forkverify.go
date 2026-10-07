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
	// is not implemented — see docs/improvement_spec.md item #6.
	KernelPath string
	RootfsPath string
}

func NewForkVerifyServer(compiler *CompilerServer, orchestrator *firecracker.Orchestrator, kernelPath, rootfsPath string) *ForkVerifyServer {
	return &ForkVerifyServer{
		compiler:     compiler,
		orchestrator: orchestrator,
		KernelPath:   kernelPath,
		RootfsPath:   rootfsPath,
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
		MemoryLimitMB: 512,
		CPUTimeoutMs:  pending.maxLatency,
	}

	ctx := stream.Context()
	_, memoryDriftBytes, err := s.orchestrator.SpawnAndMeasure(ctx, cfg)
	if err != nil {
		return stream.Send(&pb.ForkVerifyResponse{
			MicrovmId: microvmID,
			Verdict:   pb.ExecutionVerdict_VERDICT_0x00_ABORT,
		})
	}

	// MemoryDriftBytes above is a real, if coarse, observation of the
	// guest's memory snapshots. FilesMutated and NetworkPacketsDropped
	// are not measured — see docs/improvement_spec.md item #6 for what's
	// still missing (rootfs overlay diffing, network packet counters).
	commitHash := sha256.Sum256([]byte(microvmID + pending.agentID))

	return stream.Send(&pb.ForkVerifyResponse{
		MicrovmId: microvmID,
		DiffMetrics: &pb.StateDiffMetrics{
			MemoryDriftBytes: memoryDriftBytes,
		},
		Verdict:         pb.ExecutionVerdict_VERDICT_0x01_PASS,
		CommitReadyHash: commitHash[:],
	})
}
