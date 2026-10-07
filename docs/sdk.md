# Programmatic Client SDK Manual

Python client for hooking autonomous frameworks (CrewAI, LangGraph,
AutoGen) into the `ZKIntentCompiler` / `ForkVerifyEngine` gRPC services.

## Python Integration Reference

`SecOpsKernelClient` requires mutual TLS by default. Pass certificate
paths (or set the equivalent environment variables), or explicitly opt
into an insecure channel for local development:

```python
from secops_kernel.client import SecOpsKernelClient

# mTLS (recommended — required unless insecure=True is passed explicitly)
client = SecOpsKernelClient(
    target_address="127.0.0.1:50051",
    server_ca_cert_path="secrets/secops_ca.crt",
    client_key_path="secrets/client.key",
    client_cert_path="secrets/client.crt",
)
# equivalently, via env vars: SECOPS_SERVER_CA_CERT / SECOPS_CLIENT_KEY / SECOPS_CLIENT_CERT

agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
session_key = "runtime_session_cryptographic_root_key_2026"

# Package actions to check before execution. target_urn's subnet must be
# numeric and in [1000, 9999] for any write-privileged directive, and
# directive must be in the SYS_CALL_* namespace — both are enforced
# server-side (pkg/server.ValidateGraphStructure / CheckNode).
actions = [
    {
        "directive": "SYS_CALL_NETWORK_REDUCE",
        "target_urn": "urn:secops:aws:subnet-4521"
    }
]

result = client.compile_and_authorize_intent(agent_id, session_key, actions)
if result.get("success"):
    print(f"Token acquired safely: {result['simulation_token']}")
```

Generate a local CA/server/client certificate chain for development with
`pkg/sdk/py/certs/generate_certs.sh` (outputs to `secrets/`).

For local development only, without any mTLS setup:

```python
client = SecOpsKernelClient(target_address="127.0.0.1:50051", insecure=True)
```

This emits a `UserWarning` and must never be used against a real
deployment — see `IMPROVEMENT_SPEC.md` item #7 for why mTLS is required
by default.

## Configuration

`cmd/kernel-server` loads `configs/secops-kernel.yaml` (override with
`-config`) via `pkg/config`, and fails to start if it's missing,
malformed, or has a non-positive `engine.max_execution_window_ms` /
`engine.memory_fence_bytes`. Two fields are actually enforced today:

* `engine.max_execution_window_ms` — a ceiling on a request's
  `max_allowed_latency_ms`; requests asking for a longer execution
  window are aborted.
* `engine.memory_fence_bytes` — the default microVM memory limit.

Every other field (`taint_tracking.*`, `cryptography.attestation_mode`
/ `zk_circuit_path`, `fail_safe.*`) is parsed and shape-validated but
not yet wired to any behavior — see `pkg/config/config.go`'s field
comments for specifics, and `IMPROVEMENT_SPEC.md` item #14.
