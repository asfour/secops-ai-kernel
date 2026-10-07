package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/kerncode"
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

	// maxExecutionWindow is a server-enforced ceiling on a request's
	// MaxAllowedLatencyMs, sourced from configs/secops-kernel.yaml's
	// engine.max_execution_window_ms. Zero means no ceiling is enforced
	// (used by NewCompilerServer's zero-value default for tests and
	// callers that don't load a config).
	maxExecutionWindow time.Duration

	mu      sync.Mutex
	pending map[string]*pendingCompilation
}

// NewCompilerServer builds a CompilerServer with no execution-window
// ceiling. Use NewCompilerServerWithCeiling to enforce one.
func NewCompilerServer() *CompilerServer {
	return &CompilerServer{
		pending: make(map[string]*pendingCompilation),
	}
}

// NewCompilerServerWithCeiling builds a CompilerServer that rejects any
// request whose MaxAllowedLatencyMs exceeds maxExecutionWindow.
func NewCompilerServerWithCeiling(maxExecutionWindow time.Duration) *CompilerServer {
	return &CompilerServer{
		maxExecutionWindow: maxExecutionWindow,
		pending:            make(map[string]*pendingCompilation),
	}
}

func (s *CompilerServer) CompileZKIntent(ctx context.Context, req *pb.CompileZKIntentRequest) (*pb.CompileZKIntentResponse, error) {
	now := time.Now()

	requested := time.Duration(req.GetMaxAllowedLatencyMs()) * time.Millisecond
	if s.maxExecutionWindow > 0 && requested > s.maxExecutionWindow {
		// Consistent with the CheckGraph ABORT path below: the verdict in
		// the response is the signal to the caller, not a gRPC-level
		// error, so a client that only checks Verdict handles both cases
		// the same way.
		log.Printf("agent=%s: %s: requested %s exceeds configured ceiling %s",
			req.GetAgentId(), kerncode.ExecutionWindowExceedsConfiguredCeiling, requested, s.maxExecutionWindow)
		return &pb.CompileZKIntentResponse{
			Verdict:                pb.ExecutionVerdict_VERDICT_0x00_ABORT,
			CompilationTimestampNs: now.UnixNano(),
		}, nil
	}

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
