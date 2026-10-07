# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SecOps Kernel is a prototype "zero-trust execution governor" for autonomous agent frameworks (CrewAI, LangGraph, AutoGen). The core idea: an LLM-driven agent never runs shell commands or cloud API calls directly. Instead it emits a structured `IntentGraph` (nodes = proposed system actions, edges = conditional ordering), which is sent over gRPC to a compiler/verifier that:

1. Checks the graph against formally-verified invariants (Dafny) before allowing it to run.
2. Replays it inside an isolated Firecracker microVM (`ExecuteForkVerify`) and diffs resulting state.
3. Only on a `VERDICT_0x01_PASS` is the diff allowed to apply to real infrastructure.
4. An eBPF hook at the syscall level (`tp/syscalls/sys_enter_execve`) is a last-resort kill switch for any process without a valid, non-expired token in the `active_tokens_map`.

Most of this repository is **scaffold/prototype code**, not a hardened production system: the Go services are thin wrappers, the Firecracker orchestrator spawns a real `firecracker` binary but does no real attestation, the eBPF program is a minimal token-check stub, and the "ZK proof" / "AMD SEV-SNP" / license-validator pieces are placeholders rather than implemented cryptography. Treat claims in README.md / SECURITY.md / docs/ (e.g. specific SLAs, hypervisor-escape guarantees, PGP keys) as aspirational product copy, not verified behavior — confirm against the actual code before relying on them.

## Repository layout

- `pkg/api/v2/secops_kernel.proto` — the gRPC contract: `ZKIntentCompiler` (compile an IntentGraph → verdict + simulation token), `ForkVerifyEngine` (replay in a microVM, stream state diffs), `TelemetryStreamer` (side-channel syscall/perf telemetry).
- `pkg/agent/remediation_worker.go` — example gRPC client that builds an `IntentGraph` and calls `CompileZKIntent`. Useful as the reference client pattern.
- `pkg/sandbox/firecracker/` — `orchestrator.go` spawns/tears down Firecracker microVMs; `license_validator.go` does HMAC-style OEM license checks (SHA-256 of `vendor:expiry:salt`).
- `pkg/consensus/bft_quorum.go` — a 2-of-3 Byzantine quorum over heterogeneous model proposals (agents with different `ModelArch` must agree on the same state-diff hash before it's accepted).
- `pkg/kernel/ebpf/monitor.c` — eBPF program hooking `execve`; kills (SIGKILL) any process whose PID isn't present in `active_tokens_map` or whose token has expired.
- `pkg/verify/dafny/intent_rules.dfy` — formally verified invariant: any node with `writePrivilege` must target a subnet in `[1000, 9999]`. This is checked by `dafny verify` in CI, independent of the Go code.
- `pkg/sdk/py/` — Python client SDK (`secops_kernel/client.py`, `client_mtls.py`) plus framework bridges (`crewai_bridge.py`, `langgraph_bridge.py`) that wrap agent tool calls so they go through the kernel instead of executing directly.
- `cmd/secopsctl/main.go` — CLI entrypoint: `secopsctl init` (runs `setup.sh`) and `secopsctl verify` (checks `/dev/kvm` is accessible).
- `configs/secops-kernel.yaml` — runtime policy config (timeouts, taint-tracking modes, fail-safe behavior).
- `docs/` — mkdocs site content (architecture, SDK docs, OpenAPI spec, roadmap) plus marketing-style write-ups; `docs/agent_prompt_matrix.md` is the recommended system-prompt block for agents that talk to this kernel.
- `deploy/` — Terraform (`main.tf`), a Cilium CRD, and an AWS EKS deployment guide for a production-like topology.

## Build, test, and run

Toolchain: Go 1.25, Rust (criterion benches), Python 3 (SDK), plus `protoc`, `clang`/`llvm` (eBPF), `z3` + Dafny (formal verification), and a `/dev/kvm`-capable host for Firecracker.

- Full environment bootstrap (installs system deps, downloads Firecracker, generates protobuf/gRPC stubs, compiles the eBPF object): `./setup.sh`
- Regenerate gRPC stubs only (after editing `pkg/api/v2/secops_kernel.proto`):
  ```
  protoc -I=pkg/api/v2/ --go_out=paths=source_relative:pkg/api/v2/ --go-grpc_out=paths=source_relative:pkg/api/v2/ pkg/api/v2/secops_kernel.proto
  ```
- Build Go: `go build ./...` (or a specific package, e.g. `go build ./pkg/sandbox/firecracker/...`)
- Run all Go tests with coverage: `go test -v -coverprofile=coverage.out -covermode=atomic ./...`
- Run a single Go test: `go test -v -run TestVerifyMachineLicense_Expired ./pkg/sandbox/firecracker/`
- CI enforces an 80% statement coverage floor via `go tool cover -func=coverage.out`.
- Verify Dafny invariants: `dafny verify --solver-path=/usr/bin/z3 pkg/verify/dafny/intent_rules.dfy`
- Compile the eBPF monitor: `clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c pkg/kernel/ebpf/monitor.c -o pkg/kernel/ebpf/monitor.o`
- Rust benchmarks: `cargo bench` (defined in `Cargo.toml` / `benches/kernel_performance_tests.rs`)
- Python SDK tests: `python pkg/sdk/py/test_client.py` (networked integration test against a running kernel-core) and `python -m unittest pkg/sdk/py/test_crewai_bridge.py`
- Dockerized local loop (installs deps, runs Go sandbox tests, starts the remediation worker): `docker-compose up` — note the container requests `SYS_ADMIN` and `/dev/kvm` passthrough.
- `secopsctl init` / `secopsctl verify` (build with `go build ./cmd/secopsctl`) wrap `setup.sh` and the `/dev/kvm` check respectively.

CI reference: `.github/workflows/agent-attestation-ci.yml` is the canonical sequence (protoc → dafny verify → go build → go test w/ coverage gate → sha256 manifest of `configs/secops-kernel.yaml`). Mirror this order when validating changes locally.

## Conventions

- Commit messages: lower-case, `feat:` / `fix:` / `docs:` prefixes (see CONTRIBUTING.md).
- Code changes map to fixed locations: eBPF hooks under `pkg/kernel/ebpf/`, Dafny invariants under `pkg/verify/dafny/`, Python bindings under `pkg/sdk/py/`.
- Error/verdict strings follow a `0x00_SCREAMING_SNAKE_CASE` convention (e.g. `0x00_LICENSING_TOKEN_EXPIRED`, `0x00_CONSENSUS_TIMEOUT_DEADLOCK`) — match this style for new failure modes instead of plain Go errors.
- Direct pushes to `main` are not expected; work on `feature/*` branches and go through PRs, which must pass `agent-attestation-ci.yml`.
