import grpc
import hashlib
from typing import Dict, Any, List
import secops_kernel_v2_pb2 as pb
import secops_kernel_v2_pb2_grpc as pb_grpc

class SecOpsKernelClient:
    """Production SDK for SecOps Kernel programmatic machine-to-machine governance."""
    
    def __init__(self, target_address: str = "127.0.0.1:50051"):
        self.channel = grpc.insecure_channel(target_address)
        self.compiler_stub = pb_grpc.ZKIntentCompilerStub(self.channel)
        self.fork_stub = pb_grpc.ForkVerifyEngineStub(self.channel)

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
