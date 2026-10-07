# Core System Architecture Reference

> This describes the target request lifecycle; `cmd/kernel-server` and
> `pkg/server` implement the gRPC/invariant-check path, but real guest-state
> diffing, the Dafny-at-request-time link, and "atomic commit to production"
> are partially implemented or not yet wired up — see
> [improvement_spec.md](improvement_spec.md) for specifics.

SecOps Kernel wraps the autonomous AI agent execution lifecycle inside an un-bypassable hardware and memory virtualization boundary.

## The Verification Lifecycle

```mermaid
graph TD
    A[Agent Thought/Payload] --> B(gRPC Ingestion Gate)
    B --> C{Dafny Proof Circuit}
    C -- "0x00_ABORT" --> D[Terminate Stream]
    C -- "0x01_PASS" --> E[Mint Ephemeral Token]
    E --> F[Fork-and-Verify Hypervisor]
    F --> G[Firecracker MicroVM Sandbox]
    G --> H{eBPF System call checking}
    H -- "Token Drift/TTL Expired" --> I[Ring-0 SIGKILL]
    H -- "Valid State Delta" --> J[Atomic Commit to Production]
```

## Isolation Boundary Frameworks
* **Firecracker MicroVMs**: Every agent payload runs inside an isolated guest state mirror with a strict 512MB memory boundary and a **500ms execution timeout window**.
* **eBPF System call hooks**: Attaches directly onto the host's `sys_enter_execve` array table, checking permission blocks dynamically at Ring 0 out-of-band.
