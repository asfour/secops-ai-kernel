package firecracker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
)

// This file implements NetworkPacketsDropped as a real zero-trust
// enforcement signal, not passive telemetry: each microVM gets a tap
// device and a default-deny nftables policy scoped to the subnet already
// validated by pkg/server.ExtractSubnet/CheckNode. The counter on the
// catch-all drop rule *is* NetworkPacketsDropped — it counts packets the
// guest tried to send outside its authorized boundary.
//
// New convention introduced here: the "subnet" number (validated to be in
// [1000,9999] by the Dafny-mirrored invariant) has never corresponded to a
// real routable network anywhere in this codebase — it was purely a
// symbolic value for the invariant check. subnetCIDR below defines the
// first concrete mapping from that number to an actual CIDR block
// (10.<hi>.<lo>.0/24), so the firewall policy has something concrete to
// match against. This mapping has no other significance and should not be
// read as a real network topology.
//
// All of tap creation, nftables table/rule/counter management, and
// teardown require CAP_NET_ADMIN in production. They were developed and
// tested in an unprivileged user+network namespace
// (unshare --net --user --map-root-user), which grants real CAP_NET_ADMIN
// scoped to that throwaway namespace — see network_test.go.

// subnetCIDR maps a validated subnet number to a /24 CIDR block.
func subnetCIDR(subnet int) (string, error) {
	if subnet < 1000 || subnet > 9999 {
		return "", fmt.Errorf("subnet %d is outside the validated [1000,9999] range", subnet)
	}
	hi := subnet / 100
	lo := subnet % 100
	return fmt.Sprintf("10.%d.%d.0/24", hi, lo), nil
}

// shortName derives a deterministic identifier <=14 characters, safe for
// both a Linux interface name (IFNAMSIZ-1 = 15) and an nftables table
// name, from an arbitrary vmID (e.g. a simulation_token).
func shortName(prefix, vmID string) string {
	sum := sha256.Sum256([]byte(vmID))
	return prefix + hex.EncodeToString(sum[:])[:12]
}

// NetworkFence is a tap device plus a default-deny nftables policy scoped
// to a single microVM.
type NetworkFence struct {
	TapName   string
	TableName string
	GatewayIP string // host-side IP assigned to TapName
}

// SetupNetworkFence creates a tap device and a default-deny nftables
// policy for vmID, permitting traffic only to the CIDR derived from
// allowedSubnet. The caller is responsible for calling Teardown.
func SetupNetworkFence(vmID string, allowedSubnet int) (*NetworkFence, error) {
	cidr, err := subnetCIDR(allowedSubnet)
	if err != nil {
		return nil, err
	}

	fence := &NetworkFence{
		TapName:   shortName("fc", vmID),
		TableName: shortName("secops_", vmID),
		GatewayIP: "169.254.0.1/30", // link-local, host side of every fence's tap; fine to repeat since each fence's tap+table are independent
	}

	steps := [][]string{
		{"ip", "tuntap", "add", fence.TapName, "mode", "tap"},
		{"ip", "addr", "add", fence.GatewayIP, "dev", fence.TapName},
		{"ip", "link", "set", fence.TapName, "up"},
		{"nft", "add", "table", "inet", fence.TableName},
		{"nft", "add", "chain", "inet", fence.TableName, "fence",
			"{ type filter hook prerouting priority -300 ; policy drop ; }"},
		{"nft", "add", "rule", "inet", fence.TableName, "fence",
			"iifname", fence.TapName, "ip", "daddr", cidr, "counter", "accept"},
		{"nft", "add", "rule", "inet", fence.TableName, "fence",
			"iifname", fence.TapName, "counter", "drop"},
	}

	for _, args := range steps {
		if err := runCommand(args); err != nil {
			_ = teardown(fence) // best-effort cleanup of whatever partially succeeded
			return nil, fmt.Errorf("setting up network fence (%v): %w", args, err)
		}
	}

	return fence, nil
}

// Teardown removes the tap device and nftables table. Safe to call on a
// partially-constructed fence (e.g. after a failed SetupNetworkFence).
func (f *NetworkFence) Teardown() error {
	return teardown(f)
}

func teardown(f *NetworkFence) error {
	// Best-effort: run both regardless of whether the first fails, and
	// report the first error encountered (if any) to the caller.
	tableErr := runCommand([]string{"nft", "delete", "table", "inet", f.TableName})
	tapErr := runCommand([]string{"ip", "link", "delete", f.TapName})
	if tableErr != nil {
		return tableErr
	}
	return tapErr
}

// CountDropped returns the current value of the fence's catch-all drop
// counter. This is a point-in-time read; callers wanting a diff (as
// Orchestrator.SpawnAndMeasure does) must read it twice and subtract.
func (f *NetworkFence) CountDropped() (uint64, error) {
	out, err := exec.Command("nft", "-j", "list", "table", "inet", f.TableName).Output()
	if err != nil {
		return 0, fmt.Errorf("listing nftables table %q: %w", f.TableName, err)
	}
	return parseDropCounter(out)
}

// nftListOutput mirrors just enough of `nft -j list table` JSON schema to
// extract a rule's counter. See
// https://wiki.nftables.org/wiki/Nftables_JSON_API for the full schema.
type nftListOutput struct {
	Nftables []struct {
		Rule *struct {
			Expr []struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
				} `json:"counter"`
				Drop json.RawMessage `json:"drop"`
			} `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

// parseDropCounter finds the rule whose expression list contains both a
// counter and a "drop" verdict (our catch-all rule — the accept rule has
// a counter too, but no "drop" key) and returns its packet count.
func parseDropCounter(nftJSON []byte) (uint64, error) {
	var out nftListOutput
	if err := json.Unmarshal(nftJSON, &out); err != nil {
		return 0, fmt.Errorf("parsing nft JSON output: %w", err)
	}
	for _, item := range out.Nftables {
		if item.Rule == nil {
			continue
		}
		var counter *uint64
		isDrop := false
		for _, expr := range item.Rule.Expr {
			if expr.Counter != nil {
				v := expr.Counter.Packets
				counter = &v
			}
			if expr.Drop != nil {
				isDrop = true
			}
		}
		if isDrop && counter != nil {
			return *counter, nil
		}
	}
	return 0, fmt.Errorf("no counting drop rule found in nft output")
}

// ProbeCapability verifies tap+nftables fencing actually works on this
// host by creating and immediately tearing down a throwaway fence.
// Intended for a one-time startup check (mirroring
// pkg/kernel/ebpftoken.Load's role for eBPF) rather than a per-request
// check, since CAP_NET_ADMIN availability doesn't change at runtime.
func ProbeCapability() error {
	f, err := SetupNetworkFence("startup-capability-probe", 1000)
	if err != nil {
		return err
	}
	return f.Teardown()
}

func runCommand(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w (stderr: %s)", args, err, stderr.String())
	}
	return nil
}
