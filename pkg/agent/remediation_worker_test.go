package main

import (
	"testing"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/server"
)

func TestBuildIntentRequest_SatisfiesServerInvariants(t *testing.T) {
	req := buildIntentRequest("agent-1", "test-session-key")

	if req.GetAgentId() != "agent-1" {
		t.Fatalf("expected AgentId 'agent-1', got %q", req.GetAgentId())
	}
	if len(req.GetAuthTokenHash()) == 0 {
		t.Fatal("expected a non-empty auth token hash")
	}

	// The whole point of this demo request is that it's accepted by the
	// real server-side checks, not just well-formed JSON.
	if err := server.CheckGraph(req.GetExecutionIntentGraph()); err != nil {
		t.Fatalf("expected buildIntentRequest's graph to satisfy pkg/server.CheckGraph, got: %v", err)
	}
}

func TestEvaluateResponse_PassReturnsNil(t *testing.T) {
	resp := &pb.CompileZKIntentResponse{Verdict: pb.ExecutionVerdict_VERDICT_0x01_PASS}
	if err := evaluateResponse(resp); err != nil {
		t.Fatalf("expected PASS to return nil, got: %v", err)
	}
}

func TestEvaluateResponse_AbortReturnsError(t *testing.T) {
	resp := &pb.CompileZKIntentResponse{Verdict: pb.ExecutionVerdict_VERDICT_0x00_ABORT}
	if err := evaluateResponse(resp); err == nil {
		t.Fatal("expected ABORT to return a non-nil error")
	}
}
