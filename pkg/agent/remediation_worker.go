package main

import (
	"context"
	"crypto/sha256"
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

	tokenString := "runtime_session_cryptographic_root_key_2026"
	tokenHash := sha256.Sum256([]byte(tokenString))

	intentRequest := &pb.CompileZKIntentRequest{
		AgentId:             TargetAgentUUID,
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

	log.Printf("[Machine Stream] Dispatching Intent Matrix to ZKCompiler layer...")

	response, err := compilerClient.CompileZKIntent(ctx, intentRequest)
	if err != nil {
		log.Fatalf("Execution denied at OS Kernel layer: %v", err)
	}

	if response.Verdict == pb.ExecutionVerdict_VERDICT_0x01_PASS {
		log.Printf("[Attestation Locked] Simulation token acquired: %s", response.SimulationToken)
	} else {
		log.Fatalf("[CRITICAL HALT] Kernel rejected compiled execution logic parameters. Aborting thread.")
	}
}
