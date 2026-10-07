package server

import (
	"fmt"
	"regexp"
	"strconv"

	pb "secops-kernel/pkg/api/v2"
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
// (docs/improvement_spec.md item #5). CheckNode/CheckGraph is the runtime
// counterpart — it must be kept in sync with intent_rules.dfy by hand until
// the two are generated from a single source.

var subnetDigits = regexp.MustCompile(`subnet-([0-9]+)`)

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

// CheckNode mirrors intent_rules.dfy's SystemInvariant predicate for a
// single node. A nil error means the node satisfies the invariant.
func CheckNode(node *pb.IntentNode) error {
	if !IsWritePrivileged(node.GetActionDirective()) {
		return nil
	}
	subnet, err := ExtractSubnet(node.GetTargetResourceUrn())
	if err != nil {
		return fmt.Errorf("node %s: write-privileged action has invalid target: %w", node.GetNodeId(), err)
	}
	if !IsValidSubnet(subnet) {
		return fmt.Errorf("node %s: write-privileged action targets subnet %d outside [1000,9999]", node.GetNodeId(), subnet)
	}
	return nil
}

// CheckGraph mirrors intent_rules.dfy's VerifyGraphArray: PASS only if every
// node in the graph satisfies SystemInvariant.
func CheckGraph(graph *pb.IntentGraph) error {
	if graph == nil {
		return fmt.Errorf("execution_intent_graph is required")
	}
	for _, node := range graph.GetNodes() {
		if err := CheckNode(node); err != nil {
			return err
		}
	}
	return nil
}
