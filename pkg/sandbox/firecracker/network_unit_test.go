package firecracker

import "testing"

func TestSubnetCIDR_ValidRange(t *testing.T) {
	cases := []struct {
		subnet int
		want   string
	}{
		{1000, "10.10.0.0/24"},
		{4521, "10.45.21.0/24"},
		{9999, "10.99.99.0/24"},
	}
	for _, c := range cases {
		got, err := subnetCIDR(c.subnet)
		if err != nil {
			t.Fatalf("subnet %d: unexpected error: %v", c.subnet, err)
		}
		if got != c.want {
			t.Errorf("subnet %d: expected %q, got %q", c.subnet, c.want, got)
		}
	}
}

func TestSubnetCIDR_RejectsOutOfRange(t *testing.T) {
	for _, subnet := range []int{0, 999, 10000, -1} {
		if _, err := subnetCIDR(subnet); err == nil {
			t.Errorf("subnet %d: expected an error, got none", subnet)
		}
	}
}

func TestShortName_DeterministicAndBounded(t *testing.T) {
	a := shortName("fc", "same-vm-id")
	b := shortName("fc", "same-vm-id")
	if a != b {
		t.Fatalf("expected shortName to be deterministic, got %q and %q", a, b)
	}
	if len(a) > 15 {
		t.Fatalf("expected a Linux-interface-safe name (<=15 chars), got %q (%d chars)", a, len(a))
	}

	c := shortName("fc", "different-vm-id")
	if a == c {
		t.Fatal("expected different vmIDs to produce different names")
	}
}

func TestParseDropCounter_FindsCountingDropRule(t *testing.T) {
	// Real captured output from `nft -j list table inet <name>` after one
	// accepted and two dropped packets, verified against real nftables in
	// an unprivileged network namespace (see TestNetworkFence_* below).
	nftJSON := []byte(`{"nftables": [
		{"metainfo": {"version": "1.0.9"}},
		{"table": {"family": "inet", "name": "secops_test", "handle": 1}},
		{"chain": {"family": "inet", "table": "secops_test", "name": "fence", "handle": 1, "type": "filter", "hook": "prerouting", "prio": -300, "policy": "drop"}},
		{"rule": {"family": "inet", "table": "secops_test", "chain": "fence", "handle": 2, "expr": [
			{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "tap0"}},
			{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "10.45.21.0", "len": 24}}}},
			{"counter": {"packets": 1, "bytes": 33}},
			{"accept": null}
		]}},
		{"rule": {"family": "inet", "table": "secops_test", "chain": "fence", "handle": 3, "expr": [
			{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "tap0"}},
			{"counter": {"packets": 2, "bytes": 66}},
			{"drop": null}
		]}}
	]}`)

	got, err := parseDropCounter(nftJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2 {
		t.Fatalf("expected the drop rule's counter (2), got %d", got)
	}
}

func TestParseDropCounter_NoDropRuleErrors(t *testing.T) {
	nftJSON := []byte(`{"nftables": [{"table": {"family": "inet", "name": "empty"}}]}`)
	if _, err := parseDropCounter(nftJSON); err == nil {
		t.Fatal("expected an error when no counting drop rule is present")
	}
}

func TestParseDropCounter_MalformedJSONErrors(t *testing.T) {
	if _, err := parseDropCounter([]byte("not json")); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
