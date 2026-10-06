# Contributing to SecOps Kernel Core

This platform operates as a zero-human, machine-to-machine infrastructure safety layer. To preserve code quality and protect against logic insertion attacks, all contributions must pass a strict automated verification pipeline.

## 🛠️ Secure Engineering Workflow
1. **Never commit directly to `main`**: All direct pushes are programmatically denied by repository rulesets.
2. Fork the repository and build an isolated feature tracking branch: `git checkout -b feature/your-feature-name`.
3. Align all contributions with the repository structure:
   * Low-level hooks belong inside `/pkg/kernel/ebpf/`
   * Formal safety constraints map to `/pkg/verify/dafny/`
   * Python client bindings sit in `/pkg/sdk/py/`

## 📊 Continuous Integration Gates
Every open-request modification triggers the `.github/workflows/agent-attestation-ci.yml` validation suite. Your pull request will remain blocked from merging until the following steps pass:
* Complete Proto3 syntax compliance compiling under Go 1.25.
* Formal invariant theorem tracking verifying cleanly under the Z3 SMT solver path.
* Sub-millisecond container simulation runtime benchmarks passing without variance spikes.

## ✒️ Commit Messaging Schema
We enforce strict structured commit syntax. Commits must be lower-case and prefixed with modern functional identifiers:
* `feat:` for adding core engine components (e.g., `feat: introduce eBPF ring buffer stream channel`)
* `fix:` for code adjustments (e.g., `fix: align memory offset alignment on x86 hypervisors`)
* `docs:` for modifying technical layouts or reference pages.
