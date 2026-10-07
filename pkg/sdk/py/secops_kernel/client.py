import grpc
import hashlib
import os
import warnings
from typing import Dict, Any, List, Optional
import secops_kernel_v2_pb2 as pb
import secops_kernel_v2_pb2_grpc as pb_grpc


class SecOpsKernelClient:
    """Client SDK for SecOps Kernel machine-to-machine governance.

    Requires mutual TLS by default. Previously this client used
    grpc.insecure_channel unconditionally regardless of what SECURITY.md
    claims about mTLS enforcement (IMPROVEMENT_SPEC.md item #7).
    Pass explicit cert paths (or set SECOPS_SERVER_CA_CERT /
    SECOPS_CLIENT_KEY / SECOPS_CLIENT_CERT), or pass insecure=True to
    opt into an unauthenticated channel for local development only.
    """

    def __init__(
        self,
        target_address: str = "127.0.0.1:50051",
        server_ca_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        insecure: bool = False,
    ):
        server_ca_cert_path = server_ca_cert_path or os.getenv("SECOPS_SERVER_CA_CERT")
        client_key_path = client_key_path or os.getenv("SECOPS_CLIENT_KEY")
        client_cert_path = client_cert_path or os.getenv("SECOPS_CLIENT_CERT")
        have_certs = server_ca_cert_path and client_key_path and client_cert_path

        if have_certs:
            self.channel = grpc.secure_channel(
                target_address,
                self._load_credentials(server_ca_cert_path, client_key_path, client_cert_path),
            )
        elif insecure:
            warnings.warn(
                "SecOpsKernelClient is connecting WITHOUT mTLS (insecure=True). "
                "Do not use this outside local development.",
                stacklevel=2,
            )
            self.channel = grpc.insecure_channel(target_address)
        else:
            raise ValueError(
                "SecOpsKernelClient requires mTLS certificates by default. Pass "
                "server_ca_cert_path/client_key_path/client_cert_path (or set "
                "SECOPS_SERVER_CA_CERT/SECOPS_CLIENT_KEY/SECOPS_CLIENT_CERT), or "
                "explicitly pass insecure=True for local development only."
            )

        self.compiler_stub = pb_grpc.ZKIntentCompilerStub(self.channel)
        self.fork_stub = pb_grpc.ForkVerifyEngineStub(self.channel)

    @staticmethod
    def _load_credentials(server_ca_cert_path: str, client_key_path: str, client_cert_path: str):
        with open(server_ca_cert_path, 'rb') as f:
            server_ca_bytes = f.read()
        with open(client_key_path, 'rb') as f:
            client_key_bytes = f.read()
        with open(client_cert_path, 'rb') as f:
            client_cert_bytes = f.read()
        return grpc.ssl_channel_credentials(
            root_certificates=server_ca_bytes,
            private_key=client_key_bytes,
            certificate_chain=client_cert_bytes,
        )

    def compile_and_authorize_intent(
        self,
        agent_id: str,
        session_key: str,
        actions: List[Dict[str, Any]],
        max_latency_ms: int = 15
    ) -> Dict[str, Any]:
        """Compiles an agent's planned tool graph array into a verified mathematical proof."""
        token_hash = hashlib.sha256(session_key.encode('utf-8')).digest()

        nodes = []
        for i, act in enumerate(actions):
            nodes.append(pb.IntentNode(
                node_id=f"n-{i}",
                action_directive=act.get("directive", ""),
                target_resource_urn=act.get("target_urn", ""),
                argument_payload_bytes=act.get("payload", b"")
            ))

        intent_graph = pb.IntentGraph(nodes=nodes, edges=[])
        request = pb.CompileZKIntentRequest(
            agent_id=agent_id,
            auth_token_hash=token_hash,
            execution_intent_graph=intent_graph,
            max_allowed_latency_ms=max_latency_ms
        )

        try:
            response = self.compiler_stub.CompileZKIntent(request)
            return {
                "verdict": response.verdict,
                "simulation_token": response.simulation_token,
                "proof_bytes": response.zk_proof_payload_bytes.hex(),
                "success": response.verdict == pb.ExecutionVerdict.VERDICT_0x01_PASS
            }
        except grpc.RpcError as e:
            return {"success": False, "error": str(e.details())}

    def close(self):
        self.channel.close()
