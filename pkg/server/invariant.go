package server

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/kerncode"
)

// This file is the Go-side enforcement of the same invariant proved in
// pkg/verify/dafny/intent_rules.dfy:
//
//	predicate IsValidSubnet(subnet: int) { subnet >= 1000 && subnet <= 9999 }
//	predicate SystemInvariant(node: ActionNode) {
//	  node.writePrivilege ==> IsValidSubnet(node.targetSubnet)
//	}
//
// `dafny verify` only proves that model is internally consistent; it does
// not run against what this service actually does with an IntentGraph
// (IMPROVEMENT_SPEC.md item #5). CheckNode/CheckGraph is the runtime
// counterpart — it must be kept in sync with intent_rules.dfy by hand until
// the two are generated from a single source.
//
// ValidateGraphStructure (IMPROVEMENT_SPEC.md item #13) is a separate,
// earlier check: before any node is judged against the subnet invariant at
// all, the graph itself must be well-formed — unique non-empty node IDs,
// edges that reference real nodes, no cycles (an "IntentGraph" is meant to
// be a DAG of steps), and bounded payload sizes.

const maxArgumentPayloadBytes = 4096

var subnetDigits = regexp.MustCompile(`subnet-([0-9]+)`)

// allowedDirectivePrefix constrains action_directive to the documented
// SYS_CALL_* namespace (see docs/agent_prompt_matrix.md) instead of
// accepting an arbitrary string the eventual executor must interpret.
const allowedDirectivePrefix = "SYS_CALL_"

// readOnlyDirectives are action_directive values that do not mutate state
// and are therefore exempt from the subnet invariant, mirroring the Dafny
// model's writePrivilege flag (which this proto schema does not carry
// explicitly — so it must be derived from the directive name).
var readOnlyDirectives = map[string]bool{
	"SYS_CALL_READ_STATUS":     true,
	"SYS_CALL_READ_TELEMETRY":  true,
	"SYS_CALL_QUERY_INVENTORY": true,
}

// IsWritePrivileged reports whether directive mutates infrastructure state
// and must therefore satisfy IsValidSubnet.
func IsWritePrivileged(directive string) bool {
	return !readOnlyDirectives[directive]
}

// ExtractSubnet parses the numeric subnet component out of a
// target_resource_urn like "urn:secops:aws:subnet-1234". It returns an
// error if the URN has no parseable subnet digits.
func ExtractSubnet(urn string) (int, error) {
	m := subnetDigits.FindStringSubmatch(urn)
	if m == nil {
		return 0, fmt.Errorf("no subnet identifier found in urn %q", urn)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("subnet identifier in urn %q is not numeric: %w", urn, err)
	}
	return n, nil
}

// IsValidSubnet mirrors intent_rules.dfy's IsValidSubnet predicate exactly.
func IsValidSubnet(subnet int) bool {
	return subnet >= 1000 && subnet <= 9999
}

// ValidateGraphStructure checks that graph is well-formed independent of
// the subnet invariant: node IDs are present and unique, edges reference
// real nodes, the edge set is acyclic, and payloads are bounded.
func ValidateGraphStructure(graph *pb.IntentGraph) error {
	if graph == nil {
		return fmt.Errorf("execution_intent_graph is required: %w", kerncode.IntentGraphMalformed)
	}

	nodeIDs := make(map[string]bool, len(graph.GetNodes()))
	for _, node := range graph.GetNodes() {
		id := node.GetNodeId()
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("node has an empty node_id: %w", kerncode.IntentGraphMalformed)
		}
		if nodeIDs[id] {
			return fmt.Errorf("duplicate node_id %q: %w", id, kerncode.IntentGraphMalformed)
		}
		nodeIDs[id] = true

		if !strings.HasPrefix(node.GetActionDirective(), allowedDirectivePrefix) {
			return fmt.Errorf("node %s: action_directive %q is outside the %s* namespace: %w",
				id, node.GetActionDirective(), allowedDirectivePrefix, kerncode.IntentGraphMalformed)
		}
		if len(node.GetArgumentPayloadBytes()) > maxArgumentPayloadBytes {
			return fmt.Errorf("node %s: argument_payload_bytes is %d bytes, exceeds the %d byte limit: %w",
				id, len(node.GetArgumentPayloadBytes()), maxArgumentPayloadBytes, kerncode.IntentGraphMalformed)
		}
	}

	adjacency := make(map[string][]string, len(graph.GetEdges()))
	for _, edge := range graph.GetEdges() {
		if !nodeIDs[edge.GetFromNodeId()] {
			return fmt.Errorf("edge references unknown from_node_id %q: %w", edge.GetFromNodeId(), kerncode.IntentGraphMalformed)
		}
		if !nodeIDs[edge.GetToNodeId()] {
			return fmt.Errorf("edge references unknown to_node_id %q: %w", edge.GetToNodeId(), kerncode.IntentGraphMalformed)
		}
		adjacency[edge.GetFromNodeId()] = append(adjacency[edge.GetFromNodeId()], edge.GetToNodeId())
	}

	if cyclePath := findCycle(adjacency); cyclePath != "" {
		return fmt.Errorf("edges form a cycle through node %q: %w", cyclePath, kerncode.IntentGraphMalformed)
	}

	return nil
}

// findCycle returns a node ID on a cycle, or "" if adjacency is acyclic.
func findCycle(adjacency map[string][]string) string {
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := make(map[string]int)

	var visit func(node string) bool
	visit = func(node string) bool {
		switch state[node] {
		case visiting:
			return true
		case done:
			return false
		}
		state[node] = visiting
		for _, next := range adjacency[node] {
			if visit(next) {
				return true
			}
		}
		state[node] = done
		return false
	}

	for node := range adjacency {
		if state[node] == unvisited && visit(node) {
			return node
		}
	}
	return ""
}

// CheckNode mirrors intent_rules.dfy's SystemInvariant predicate for a
// single node. A nil error means the node satisfies the invariant.
func CheckNode(node *pb.IntentNode) error {
	if !IsWritePrivileged(node.GetActionDirective()) {
		return nil
	}
	subnet, err := ExtractSubnet(node.GetTargetResourceUrn())
	if err != nil {
		return fmt.Errorf("node %s: write-privileged action has invalid target: %w: %w",
			node.GetNodeId(), err, kerncode.IntentInvariantViolation)
	}
	if !IsValidSubnet(subnet) {
		return fmt.Errorf("node %s: write-privileged action targets subnet %d outside [1000,9999]: %w",
			node.GetNodeId(), subnet, kerncode.IntentInvariantViolation)
	}
	return nil
}

// CheckGraph validates graph structure first (ValidateGraphStructure), then
// mirrors intent_rules.dfy's VerifyGraphArray: PASS only if every node also
// satisfies SystemInvariant.
func CheckGraph(graph *pb.IntentGraph) error {
	if err := ValidateGraphStructure(graph); err != nil {
		return err
	}
	for _, node := range graph.GetNodes() {
		if err := CheckNode(node); err != nil {
			return err
		}
	}
	return nil
}
