package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	pb "secops-kernel/pkg/api/v2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	KernelTargetAddress = "127.0.0.1:50051"
	TargetAgentUUID     = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
)

func main() {
	conn, err := grpc.Dial(KernelTargetAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("gRPC core channel initialization error: %v", err)
	}
	defer conn.Close()

	compilerClient := pb.NewZKIntentCompilerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	intentRequest := buildIntentRequest(TargetAgentUUID, "runtime_session_cryptographic_root_key_2026")

	log.Printf("[Machine Stream] Dispatching Intent Matrix to ZKCompiler layer...")

	response, err := compilerClient.CompileZKIntent(ctx, intentRequest)
	if err != nil {
		log.Fatalf("Execution denied at OS Kernel layer: %v", err)
	}

	if err := evaluateResponse(response); err != nil {
		log.Fatalf("[CRITICAL HALT] %v", err)
	}
	log.Printf("[Attestation Locked] Simulation token acquired: %s", response.SimulationToken)
}

// buildIntentRequest constructs the demo CompileZKIntentRequest this
// worker sends. Pulled out of main so it can be tested without a network
// dial: the target subnet and directive must satisfy pkg/server's
// write-privilege/subnet invariant (SYS_CALL_* namespace, numeric subnet
// in [1000, 9999]) or the kernel will abort it.
func buildIntentRequest(agentID, sessionKey string) *pb.CompileZKIntentRequest {
	tokenHash := sha256.Sum256([]byte(sessionKey))

	return &pb.CompileZKIntentRequest{
		AgentId:             agentID,
		AuthTokenHash:       tokenHash[:],
		MaxAllowedLatencyMs: 15,
		ExecutionIntentGraph: &pb.IntentGraph{
			Nodes: []*pb.IntentNode{
				{
					NodeId:          "node-0x01",
					ActionDirective: "SYS_CALL_NETWORK_REDUCE",
					// Must be a purely numeric subnet in [1000, 9999] to satisfy
					// the write-privilege invariant (pkg/verify/dafny/intent_rules.dfy,
					// enforced at runtime in pkg/server.CheckNode).
					TargetResourceUrn: "urn:secops:aws:subnet-4521",
				},
			},
			Edges: []*pb.IntentEdge{},
		},
	}
}

// evaluateResponse returns nil only on VERDICT_0x01_PASS, pulled out of
// main so the pass/fail branch is testable independent of an actual RPC.
func evaluateResponse(resp *pb.CompileZKIntentResponse) error {
	if resp.GetVerdict() != pb.ExecutionVerdict_VERDICT_0x01_PASS {
		return fmt.Errorf("kernel rejected compiled execution logic parameters (verdict=%s)", resp.GetVerdict())
	}
	return nil
}
