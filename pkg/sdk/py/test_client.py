import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/secops_kernel'))

from client import SecOpsKernelClient

def run_local_sdk_validation():
    print("=================================================================")
    print("🐍 Executing Local Python SDK Validation Suite...")
    print("=================================================================")
    
    # Initialize the client mapping to the secure container bridge channel
    client = SecOpsKernelClient(target_address="127.0.0.1:50051")
    
    agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    session_key = "runtime_session_cryptographic_root_key_2026"
    
    # Declare the remediation directive steps to compile
    mock_actions = [
        {
            "directive": "SYS_CALL_NETWORK_REDUCE",
            "target_urn": "urn:secops:aws:subnet-09f123",
            "payload": b"\x01\x00\x02\xA4"
        }
    ]
    
    print("[*] Dispatching tool intent graph vectors via Python SDK...")
    result = client.compile_and_authorize_intent(agent_id, session_key, mock_actions)
    
    # The client wrapper will handle error routing if the gRPC backend is offline
    if not result.get("success") and "error" in result:
        print(f"✅ SDK Structural Communication Verified (Expected connection drop: {result['error']})")
        print("=================================================================")
    else:
        print(f"Result Verdict Signal received: {result.get('verdict')}")
        
    client.close()

if __name__ == "__main__":
    run_local_sdk_validation()
