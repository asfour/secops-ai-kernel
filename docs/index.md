# Secure Agentic Autonomy at the Kernel Boundary

Traditional AI application firewalls treat autonomous agents like human
users — wrapping them in semantic filters or text pattern rules. That
breaks down against multi-turn prompt injection and execution drift.

**SecOps Kernel** instead treats an agent's proposed infrastructure
actions as untrusted input to a gRPC compiler: every action is compiled
into a structured `IntentGraph`, checked against explicit invariants, and
replayed inside an isolated Firecracker microVM before anything is
reported as safe to commit. See [Architecture](architecture.md) for the
full request lifecycle and what each stage actually verifies today.

## Core Architectural Pillars

### 1. Invariant-Checked Intent Compilation
Every `IntentGraph` is validated for structure (unique node IDs, no
dangling edges, no cycles, a bounded `SYS_CALL_*` directive namespace,
bounded payload size) and then checked against a write-privilege/subnet
invariant that mirrors a formally verified Dafny model
(`pkg/verify/dafny/intent_rules.dfy`). A violation aborts before a
simulation token is ever minted.

### 2. Fork-and-Verify MicroVMs
A passing intent is replayed inside an isolated Firecracker microVM,
driven over Firecracker's real REST API. The kernel takes a memory
snapshot just after boot and another partway through the execution
window, and reports a real byte-level diff as part of the verdict.

### 3. Ring-0 eBPF Interception
An eBPF probe attaches to the host's `sys_enter_execve` tracepoint.
Every process the kernel manages is granted a time-boxed token in a BPF
map at the exact moment it execs; anything without a live token is
`SIGKILL`'d at Ring-0 immediately.

### 4. Byzantine Fault Tolerant (BFT) Quorums
For actions requiring multi-agent agreement, proposals must carry a
valid signature from a registered agent identity. Quorum requires both
enough distinct signed agents and enough distinct model architectures
agreeing on the same state-diff hash — a single compromised agent cannot
manufacture consensus by claiming multiple architectures itself.

---

This project is under active development.
[`IMPROVEMENT_SPEC.md`](https://github.com/asfour/secops-ai-kernel/blob/main/IMPROVEMENT_SPEC.md)
at the repository root tracks what's implemented versus still
aspirational in more detail than belongs on a published page.
