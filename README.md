# SecOps Kernel v2.0-Machine Architecture & Micro-Protocol Manual

> **Status: early-stage, under active development.** A real gRPC server,
> eBPF enforcement, signed BFT consensus, and Firecracker-backed state
> diffing exist and are tested — but this document still describes target
> design in places. For what's implemented versus still aspirational, see
> [IMPROVEMENT_SPEC.md](IMPROVEMENT_SPEC.md) and [CLAUDE.md](CLAUDE.md).
> Specific guarantees below ("un-bypassable", hardware-level resets, etc.)
> are design intent, not verified behavior.

SecOps Kernel is a headless, zero-human, immutable operating system layer explicitly designed to host and govern high-privilege autonomous security agents. The platform handles all actions natively via binary streaming networks, completely bypassing the text overhead of traditional legacy firewalls.

## Binary Stream Handshake Specification

To interface with the kernel, autonomous machine runtimes must satisfy a strict 3-way cryptographic lifecycle handshake.

### Step 1: Compilation Phase
Submit the planned tool graph array payload to `/secops.kernel.v2.ZKIntentCompiler/CompileZKIntent`. The runtime must convert natural-language strategy weights into structural programmatic `IntentGraph` nodes.

### Step 2: Isolated Virtualization Loop
Extract the returned `simulation_token` and invoke `ExecuteForkVerify`. The kernel instantiates a transient Firecracker microVM instance, cloning production metadata completely out-of-band. 

### Step 3: Atomic Commit Delta
The agent performs system calls inside the microVM. If the resulting system configuration delta variance matches a binary matrix score of `0x01_PASS`, the hypervisor applies the diff payload to production infrastructure.

## Byte-Offset Structure for Side-Channel Ingestion

Out-of-band hypervisor telemetry reads execution traces directly via memory side-channels to verify the agent's absolute operational alignment. The binary telemetry payload frames use a fixed-width byte array topology:

| Byte Offset | Data Type | Field Definition | Hard System Constraints |
| :--- | :--- | :--- | :--- |
| `0x00 - 0x07` | `uint64` | Sequence ID | Sequential monotonically increasing index. |
| `0x08 - 0x0F` | `int64` | Unix Nanosecond Timestamp | Enforces global state order across engines. |
| `0x10 - 0x1F` | `bytes16` | Agent Identity UUID | Hard-gated matching cryptographic root hashes. |
| `0x20 - 0x27` | `uint64` | Total CPU Instruction Count | Max ceiling allowed per invocation before drop: `2,000,000`. |
| `0x28 - 0x2B` | `uint32` | L3 Cache Miss Delta Variation | Exceeding a variance threshold of `500%` triggers instant purge. |
| `0x2C - 0x3C` | `bytes16` | Core eBPF Trapped Call Signature | Evaluated by the kernel system filter at Ring 0. |

If the data parsing pipeline detects a structural mismatch or if a transaction remains active beyond a hard timeout frame of **500 milliseconds**, the target virtualized sandbox is instantly subjected to an ACPI hardware-level reset.
