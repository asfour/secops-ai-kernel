package server

import (
	"context"
	"testing"
	"time"

	pb "secops-kernel/pkg/api/v2"
)

func TestCompileZKIntent_PassRegistersPendingToken(t *testing.T) {
	s := NewCompilerServer()
	req := &pb.CompileZKIntentRequest{
		AgentId:             "agent-1",
		MaxAllowedLatencyMs: 15,
		ExecutionIntentGraph: &pb.IntentGraph{
			Nodes: []*pb.IntentNode{
				{NodeId: "n-0", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			},
		},
	}

	resp, err := s.CompileZKIntent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != pb.ExecutionVerdict_VERDICT_0x01_PASS {
		t.Fatalf("expected PASS, got %v", resp.Verdict)
	}
	if resp.SimulationToken == "" {
		t.Fatal("expected a non-empty simulation token")
	}

	pending, ok := s.takePending(resp.SimulationToken)
	if !ok {
		t.Fatal("expected simulation token to be redeemable exactly once")
	}
	if pending.agentID != "agent-1" {
		t.Fatalf("expected pending agentID 'agent-1', got %q", pending.agentID)
	}

	if _, ok := s.takePending(resp.SimulationToken); ok {
		t.Fatal("expected simulation token to be consumed after first take")
	}
}

func TestCompileZKIntent_AbortsOnInvariantViolation(t *testing.T) {
	s := NewCompilerServer()
	req := &pb.CompileZKIntentRequest{
		AgentId: "agent-2",
		ExecutionIntentGraph: &pb.IntentGraph{
			Nodes: []*pb.IntentNode{
				{NodeId: "n-0", ActionDirective: "SYS_CALL_IAM_ROTATE", TargetResourceUrn: "urn:secops:aws:subnet-1"},
			},
		},
	}

	resp, err := s.CompileZKIntent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != pb.ExecutionVerdict_VERDICT_0x00_ABORT {
		t.Fatalf("expected ABORT, got %v", resp.Verdict)
	}
	if resp.SimulationToken != "" {
		t.Fatal("expected no simulation token to be minted on ABORT")
	}
}

func TestCompileZKIntent_AbortsWhenExceedingConfiguredCeiling(t *testing.T) {
	s := NewCompilerServerWithCeiling(500 * time.Millisecond)
	req := &pb.CompileZKIntentRequest{
		AgentId:             "agent-3",
		MaxAllowedLatencyMs: 5000, // exceeds the 500ms ceiling
		ExecutionIntentGraph: &pb.IntentGraph{
			Nodes: []*pb.IntentNode{
				{NodeId: "n-0", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			},
		},
	}

	resp, err := s.CompileZKIntent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != pb.ExecutionVerdict_VERDICT_0x00_ABORT {
		t.Fatalf("expected ABORT for a request exceeding the configured ceiling, got %v", resp.Verdict)
	}
	if resp.SimulationToken != "" {
		t.Fatal("expected no simulation token to be minted when the ceiling is exceeded")
	}
}

func TestCompileZKIntent_PassesWithinConfiguredCeiling(t *testing.T) {
	s := NewCompilerServerWithCeiling(500 * time.Millisecond)
	req := &pb.CompileZKIntentRequest{
		AgentId:             "agent-4",
		MaxAllowedLatencyMs: 100,
		ExecutionIntentGraph: &pb.IntentGraph{
			Nodes: []*pb.IntentNode{
				{NodeId: "n-0", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			},
		},
	}

	resp, err := s.CompileZKIntent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != pb.ExecutionVerdict_VERDICT_0x01_PASS {
		t.Fatalf("expected PASS for a request within the ceiling, got %v", resp.Verdict)
	}
}
