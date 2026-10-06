# Programmatic Client SDK Manual

Deploy the client library natively to hook autonomous frameworks directly into the SecOps Kernel safety gates.

## Python Integration Reference

```python
from secops_kernel.client import SecOpsKernelClient

# Initialize connection mapping to the local gRPC mesh network
client = SecOpsKernelClient(target_address="127.0.0.1:50051")

agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
session_key = "runtime_session_cryptographic_root_key_2026"

# Package actions to check before execution
actions = [
    {
        "directive": "SYS_CALL_NETWORK_REDUCE",
        "target_urn": "urn:secops:aws:subnet-09f123"
    }
]

# Dispatch compiled tool graph to the ZKIntentCompiler service
result = client.compile_and_authorize_intent(agent_id, session_key, actions)
if result.get("success"):
    print(f"Token acquired safely: {result['simulation_token']}")
```

## Configuration Manifest Specs
Define your system boundary parameters inside `configs/secops-kernel.yaml`:
* `engine.max_execution_window_ms`: `500`
* `cryptography.token_ttl_ms`: `10`
* `fail_safe.on_non_determinism`: `0x00_ABORT`
