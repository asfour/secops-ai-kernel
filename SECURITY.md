# Vulnerability Disclosure Policy (SECURITY.md)

We take the security of the **SecOps Kernel** architecture seriously. As an immutable autonomous security engine operating at the kernel layer, vulnerabilities inside this codebase could lead to hypervisor escapes or privilege drifts. 

If you discover a security vulnerability, we request that you report it to us confidentially before public disclosure.

## Supported Versions

Only the active machine release branch is evaluated for security patches. Please update your container runtimes to the newest minor build before logging vulnerabilities.

| Version | Supported | Encryption Enforcement | Patch Loop Window |
| :--- | :---: | :--- | :--- |
| **v2.x.x-Machine** | ✅ Yes | Enforced (mTLS Key Encrypted) | 48 Hours Fast-Path |
| v1.x.x-Legacy | ❌ No | Un-encrypted | Deprecated |

## Reporting a Vulnerability

**Do not log security vulnerabilities via public GitHub Issues.** 

To report a vulnerability, please utilize one of the two secure channels below:

### Option A: GitHub Private Security Advisories
1. Navigate to the **Security** tab of this repository on GitHub.com.
2. Select **Advisories** from the left-hand sidebar menu.
3. Click the **Report a vulnerability** button to open a private, encrypted staging loop directly with the repository maintainers.

### Option B: Encrypted Maintainer Email
Email our core triage team at `security-triage@secops-kernel.io`. For critical remote code execution (RCE) vectors or eBPF bypasses, you must encrypt your payload message string using our public PGP identity block:

```text
Fingerprint: 8F43 89A2 B8C1 D4FA E7DE C11D 0A76 5005 1F82 AA01
```

Please include the following machine-readable matrices inside your brief:
* **Target Vulnerability URN Vector** (e.g., `pkg/kernel/ebpf/monitor.c`)
* **Mathematical Proof of Concept (PoC)** or an executable curl snippet breaking the Dafny logic graph.
* **Estimated Blast Radius Impact Assessment** (e.g., Hypervisor Breakout, Token Reuse).

## The Disclosure & Remediation Timeline

Upon receipt of a valid threat signature profile, the maintainer team enforces a **90-day responsible disclosure isolation loop**:
1. **T+24 Hours**: Maintainers confirm the receipt of the payload and establish a private GitHub advisory branch.
2. **T+72 Hours**: Technical team verifies the bug against our integrated Rust Criterion validation suite.
3. **T+14 Days**: A clean upstream patch branch is prepared and staged through the automated `.github/workflows/agent-attestation-ci.yml` pipeline.
4. **T+30 Days**: The coordinated release advisory goes live, and the updated `monitor.o` binary is automatically pushed to the GitHub Releases page.
