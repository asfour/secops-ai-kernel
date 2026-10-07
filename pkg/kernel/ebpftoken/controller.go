// Package ebpftoken loads the compiled Ring-0 monitor (pkg/kernel/ebpf/monitor.c)
// and manages the active_tokens_map it reads from. Without this controller the
// monitor's map is always empty, so every execve on the host gets SIGKILL'd
// regardless of whether it came from a kernel-governed process. See
// docs/improvement_spec.md item #3.
package ebpftoken

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// tokenMetadata mirrors `struct token_metadata` in pkg/kernel/ebpf/monitor.c:
//
//	struct token_metadata {
//	    __u64 agent_id;
//	    __u32 permission_mask;
//	    __u64 execution_window_expiry_ns;
//	};
type tokenMetadata struct {
	AgentID               uint64
	PermissionMask        uint32
	_                     uint32 // compiler padding to align the next __u64
	ExecutionWindowExpiry uint64 // unix nanoseconds
}

const activeTokensMapName = "active_tokens_map"

// Controller grants and revokes execution tokens for process IDs in the
// eBPF active_tokens_map, keyed exactly as monitor.c expects: by PID.
type Controller struct {
	coll *ebpf.Collection
	tok  *ebpf.Map
}

// Load opens the compiled BPF object at objectPath (normally
// pkg/kernel/ebpf/monitor.o, produced by setup.sh / CI) and pins a handle to
// its active_tokens_map. It does not attach the tracepoint program — that is
// a privileged, host-wide operation intentionally left to an explicit
// Attach() call so callers (and tests) can exercise the map without taking
// over the host's execve path.
func Load(objectPath string) (*Controller, error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("loading bpf object %q: %w", objectPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instantiating bpf collection: %w", err)
	}

	m, ok := coll.Maps[activeTokensMapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("bpf object %q does not define map %q", objectPath, activeTokensMapName)
	}

	return &Controller{coll: coll, tok: m}, nil
}

// Attach attaches handle_execve_entry to tp/syscalls/sys_enter_execve,
// activating host-wide enforcement. From this point on, any PID without a
// live entry in active_tokens_map will be SIGKILL'd on its next execve.
func (c *Controller) Attach() (link.Link, error) {
	prog, ok := c.coll.Programs["handle_execve_entry"]
	if !ok {
		return nil, fmt.Errorf("bpf object does not define program handle_execve_entry")
	}
	l, err := attachTracepoint(prog)
	if err != nil {
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}
	return l, nil
}

// Grant authorizes pid to execute for the given ttl, under agentID /
// permissionMask bookkeeping fields that mirror the eBPF struct but are not
// currently enforced by monitor.c beyond presence + expiry.
func (c *Controller) Grant(pid uint32, agentID uint64, permissionMask uint32, ttl time.Duration) error {
	meta := tokenMetadata{
		AgentID:               agentID,
		PermissionMask:        permissionMask,
		ExecutionWindowExpiry: uint64(time.Now().Add(ttl).UnixNano()),
	}

	key := uint64(pid)
	return c.tok.Put(key, meta)
}

// Revoke immediately removes pid's token, causing its next execve to be
// killed even if the TTL granted in Grant has not yet elapsed.
func (c *Controller) Revoke(pid uint32) error {
	key := uint64(pid)
	err := c.tok.Delete(key)
	if err != nil {
		return fmt.Errorf("revoking token for pid %d: %w", pid, err)
	}
	return nil
}

// Close releases the underlying BPF collection.
func (c *Controller) Close() error {
	c.coll.Close()
	return nil
}

var _ = binary.LittleEndian // referenced to make the intended wire order explicit for reviewers
