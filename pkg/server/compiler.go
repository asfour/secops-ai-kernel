package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	pb "secops-kernel/pkg/api/v2"
)

// pendingCompilation is what CompileZKIntent hands off to ForkVerifyEngine
// via the simulation_token it returns.
type pendingCompilation struct {
	agentID         string
	graph           *pb.IntentGraph
	maxLatency      time.Duration
	compiledAtNanos int64
}

// CompilerServer implements pb.ZKIntentCompilerServer.
type CompilerServer struct {
	pb.UnimplementedZKIntentCompilerServer

	mu      sync.Mutex
	pending map[string]*pendingCompilation
}

func NewCompilerServer() *CompilerServer {
	return &CompilerServer{
		pending: make(map[string]*pendingCompilation),
	}
}

func (s *CompilerServer) CompileZKIntent(ctx context.Context, req *pb.CompileZKIntentRequest) (*pb.CompileZKIntentResponse, error) {
	now := time.Now()

	if err := CheckGraph(req.GetExecutionIntentGraph()); err != nil {
		return &pb.CompileZKIntentResponse{
			Verdict:                pb.ExecutionVerdict_VERDICT_0x00_ABORT,
			CompilationTimestampNs: now.UnixNano(),
		}, nil
	}

	token, err := newSimulationToken()
	if err != nil {
		return nil, fmt.Errorf("minting simulation token: %w", err)
	}

	// zk_proof_payload_bytes is NOT a real zero-knowledge proof. It is a
	// deterministic commitment to the compiled graph so a downstream
	// ForkVerifyEngine call can detect if the request body changed
	// between compile and fork-verify. A real ZK circuit (per
	// configs/secops-kernel.yaml's zk_circuit_path) is tracked separately
	// and must not be assumed to exist from this field's presence alone.
	proof := sha256.Sum256([]byte(req.GetExecutionIntentGraph().String()))

	s.mu.Lock()
	s.pending[token] = &pendingCompilation{
		agentID:         req.GetAgentId(),
		graph:           req.GetExecutionIntentGraph(),
		maxLatency:      time.Duration(req.GetMaxAllowedLatencyMs()) * time.Millisecond,
		compiledAtNanos: now.UnixNano(),
	}
	s.mu.Unlock()

	return &pb.CompileZKIntentResponse{
		Verdict:                pb.ExecutionVerdict_VERDICT_0x01_PASS,
		ZkProofPayloadBytes:    proof[:],
		SimulationToken:        token,
		CompilationTimestampNs: now.UnixNano(),
	}, nil
}

// takePending consumes a simulation token exactly once, so a given compiled
// intent cannot be fork-verified or committed twice.
func (s *CompilerServer) takePending(token string) (*pendingCompilation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if ok {
		delete(s.pending, token)
	}
	return p, ok
}

func newSimulationToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "st_" + hex.EncodeToString(buf), nil
}
