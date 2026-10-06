import grpc
import hashlib
from typing import Dict, Any, List
import secops_kernel_v2_pb2 as pb
import secops_kernel_v2_pb2_grpc as pb_grpc

class SecOpsKernelSecureClient:
    """Enterprise-grade Asymmetric mTLS Client SDK for SecOps Kernel OS."""
    
    def __init__(
        self, 
        target_address: str, 
        server_ca_cert_path: str, 
        client_key_path: str, 
        client_cert_path: str
    ):
        # 1. Ingest cryptographic key material vectors securely
        with open(server_ca_cert_path, 'rb') as f:
            server_ca_bytes = f.read()
        with open(client_key_path, 'rb') as f:
            client_key_bytes = f.read()
        with open(client_cert_path, 'rb') as f:
            client_cert_bytes = f.read()

        # 2. Compile mutual-TLS channel credentials stubs
        self.credentials = grpc.ssl_channel_credentials(
            root_certificates=server_ca_bytes,
            private_key=client_key_bytes,
            certificate_chain=client_cert_bytes
        )
        
        # Instantiate an encrypted, un-bypassable gRPC transport pipe
        self.channel = grpc.secure_channel(target_address, self.credentials)
        self.compiler_stub = pb_grpc.ZKIntentCompilerStub(self.channel)

    def compile_and_authorize_intent(
        self, 
        agent_id: str, 
        session_key: str, 
        actions: List[Dict[str, Any]], 
        max_latency_ms: int = 15
    ) -> Dict[str, Any]:
        """Transmits intent configurations wrapped within an mTLS wrapper frame."""
        token_hash = hashlib.sha256(session_key.encode('utf-8')).digest()
        nodes = [
            pb.IntentNode(
                node_id=f"n-{i}",
                action_directive=act.get("directive", ""),
                target_resource_urn=act.get("target_urn", ""),
                argument_payload_bytes=act.get("payload", b"")
            ) for i, act in enumerate(actions)
        ]
        
        request = pb.CompileZKIntentRequest(
            agent_id=agent_id,
            auth_token_hash=token_hash,
            execution_intent_graph=pb.IntentGraph(nodes=nodes, edges=[]),
            max_allowed_latency_ms=max_latency_ms
        )
        
        try:
            response = self.compiler_stub.CompileZKIntent(request)
            return {"success": True, "verdict": response.verdict, "simulation_token": response.simulation_token}
        except grpc.RpcError as e:
            return {"success": False, "error": str(e.details())}

    def close(self):
        self.channel.close()
