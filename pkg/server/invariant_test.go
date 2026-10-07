package server

import (
	"testing"

	pb "secops-kernel/pkg/api/v2"
)

func TestCheckNode_WritePrivilegedValidSubnet(t *testing.T) {
	node := &pb.IntentNode{
		NodeId:            "n-0",
		ActionDirective:   "SYS_CALL_NETWORK_REDUCE",
		TargetResourceUrn: "urn:secops:aws:subnet-1234",
	}
	if err := CheckNode(node); err != nil {
		t.Fatalf("expected valid subnet to pass, got error: %v", err)
	}
}

func TestCheckNode_WritePrivilegedInvalidSubnet(t *testing.T) {
	node := &pb.IntentNode{
		NodeId:            "n-1",
		ActionDirective:   "SYS_CALL_IAM_ROTATE",
		TargetResourceUrn: "urn:secops:aws:subnet-42",
	}
	if err := CheckNode(node); err == nil {
		t.Fatal("expected out-of-range subnet to fail the invariant")
	}
}

func TestCheckNode_ReadOnlyBypassesInvariant(t *testing.T) {
	node := &pb.IntentNode{
		NodeId:            "n-2",
		ActionDirective:   "SYS_CALL_READ_STATUS",
		TargetResourceUrn: "urn:secops:aws:subnet-42", // would fail if write-privileged
	}
	if err := CheckNode(node); err != nil {
		t.Fatalf("expected read-only directive to bypass the invariant, got: %v", err)
	}
}

func TestCheckNode_MalformedUrn(t *testing.T) {
	node := &pb.IntentNode{
		NodeId:            "n-3",
		ActionDirective:   "SYS_CALL_NETWORK_REDUCE",
		TargetResourceUrn: "urn:secops:aws:not-a-subnet",
	}
	if err := CheckNode(node); err == nil {
		t.Fatal("expected unparseable subnet identifier to fail the invariant")
	}
}

func TestCheckGraph_AbortsOnFirstViolation(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			{NodeId: "n-1", ActionDirective: "SYS_CALL_IAM_ROTATE", TargetResourceUrn: "urn:secops:aws:subnet-1"},
		},
	}
	if err := CheckGraph(graph); err == nil {
		t.Fatal("expected graph with one invalid node to fail")
	}
}

func TestCheckGraph_NilGraphFails(t *testing.T) {
	if err := CheckGraph(nil); err == nil {
		t.Fatal("expected nil graph to fail")
	}
}
