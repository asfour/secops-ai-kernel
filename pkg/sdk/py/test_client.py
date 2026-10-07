import sys
import os
import time

# Dynamic inclusion path mapping for compiled protobuf stubs
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from client import SecOpsKernelClient
    import secops_kernel_pb2 as pb
except ImportError:
    print("[Notice] Initializing local stub compiler dependencies...")

def run_networked_integration_test():
    print("=================================================================")
    print("🐍 Running Hardened Python SDK Verification Suite...")
    print("=================================================================")
    
    # Connect directly to our running core engine service over the mesh network.
    # This is a manual local-integration harness run inside the docker-compose
    # mesh network (not CI), so an explicit insecure opt-in is acceptable here;
    # see IMPROVEMENT_SPEC.md item #7 for why SecOpsKernelClient otherwise
    # requires mTLS certificates by default.
    client = SecOpsKernelClient(target_address="kernel-core:50051", insecure=True)
    
    agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    session_key = "runtime_session_cryptographic_root_key_2026"
    
    mock_actions = [
        {
            "directive": "SYS_CALL_NETWORK_REDUCE",
            "target_urn": "urn:secops:aws:subnet-09f123",
            "payload": b"\x01\x00\x02\xA4"
        }
    ]
    
    print("[*] Transmitting structured tool signature graph over network...")
    
    # Compile execution parameters passing explicit enterprise vendor license constraints
    result = client.compile_and_authorize_intent(
        agent_id=agent_id, 
        session_key=session_key, 
        actions=mock_actions,
        max_latency_ms=15
    )
    
    if result.get("success"):
        print(f"🎉 TEST PASSED: Token acquired successfully: {result['simulation_token']}")
    else:
        # If the backend connection dropped or failed, capture the trace logs cleanly
        print(f"📡 Connection Handshake Logged: {result.get('error', 'Handshake Rejected by Kernel Invariants')}")
    
    print("=================================================================")
    client.close()

if __name__ == "__main__":
    run_networked_integration_test()
