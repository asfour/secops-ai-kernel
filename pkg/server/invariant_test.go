package server

import (
	"errors"
	"testing"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/kerncode"
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
	err := CheckGraph(nil)
	if err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsEmptyNodeID(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsDuplicateNodeID(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed for duplicate node_id, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsEdgeToUnknownNode(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
		Edges: []*pb.IntentEdge{
			{FromNodeId: "n-0", ToNodeId: "n-does-not-exist"},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed for a dangling edge, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsCycle(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			{NodeId: "n-1", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
		Edges: []*pb.IntentEdge{
			{FromNodeId: "n-0", ToNodeId: "n-1"},
			{FromNodeId: "n-1", ToNodeId: "n-0"},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed for a cycle, got: %v", err)
	}
}

func TestValidateGraphStructure_AcceptsValidDAG(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
			{NodeId: "n-1", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
		Edges: []*pb.IntentEdge{
			{FromNodeId: "n-0", ToNodeId: "n-1"},
		},
	}
	if err := ValidateGraphStructure(graph); err != nil {
		t.Fatalf("expected a valid DAG to pass structural validation, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsDirectiveOutsideNamespace(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "DROP_TABLE_USERS", TargetResourceUrn: "urn:secops:aws:subnet-1234"},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed for a directive outside SYS_CALL_*, got: %v", err)
	}
}

func TestValidateGraphStructure_RejectsOversizedPayload(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{
				NodeId:               "n-0",
				ActionDirective:      "SYS_CALL_READ_STATUS",
				TargetResourceUrn:    "urn:secops:aws:subnet-1234",
				ArgumentPayloadBytes: make([]byte, maxArgumentPayloadBytes+1),
			},
		},
	}
	if err := ValidateGraphStructure(graph); err == nil || !errors.Is(err, kerncode.IntentGraphMalformed) {
		t.Fatalf("expected kerncode.IntentGraphMalformed for an oversized payload, got: %v", err)
	}
}

func TestPrimarySubnet_ReturnsFirstWritePrivilegedValidSubnet(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-9999"},
			{NodeId: "n-1", ActionDirective: "SYS_CALL_NETWORK_REDUCE", TargetResourceUrn: "urn:secops:aws:subnet-4521"},
		},
	}
	subnet, ok := PrimarySubnet(graph)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if subnet != 4521 {
		t.Fatalf("expected the write-privileged node's subnet 4521 (not the read-only node's 9999), got %d", subnet)
	}
}

func TestPrimarySubnet_NoWritePrivilegedNodeReturnsFalse(t *testing.T) {
	graph := &pb.IntentGraph{
		Nodes: []*pb.IntentNode{
			{NodeId: "n-0", ActionDirective: "SYS_CALL_READ_STATUS", TargetResourceUrn: "urn:secops:aws:subnet-4521"},
		},
	}
	if _, ok := PrimarySubnet(graph); ok {
		t.Fatal("expected ok=false when no node is write-privileged")
	}
}
