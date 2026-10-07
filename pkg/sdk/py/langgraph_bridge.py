import os
import sys
from typing import Dict, Any, TypedDict, Annotated, List
from langgraph.graph import StateGraph, END

# Ensure local SDK pathway mapping is active
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from client import SecOpsKernelClient

# 1. Initialize the Secure Kernel SDK connection socket
KERNEL_ADDRESS = os.getenv("SECOPS_KERNEL_ADDRESS", "127.0.0.1:50051")
# mTLS is required unless SECOPS_SERVER_CA_CERT/SECOPS_CLIENT_KEY/SECOPS_CLIENT_CERT
# are set (see secops_kernel/client.py), or the operator explicitly opts out of
# transport security for local development via SECOPS_ALLOW_INSECURE_KERNEL_CLIENT.
_ALLOW_INSECURE = os.getenv("SECOPS_ALLOW_INSECURE_KERNEL_CLIENT", "").lower() == "true"
kernel_client = SecOpsKernelClient(target_address=KERNEL_ADDRESS, insecure=_ALLOW_INSECURE)

class AgentState(TypedDict):
    """LangGraph operational state tracking structure."""
    proposed_actions: List[Dict[str, Any]]
    validation_verdict: bool
    simulation_token: str
    execution_logs: str

def secops_kernel_fence_node(state: AgentState) -> Dict[str, Any]:
    """Intercepts LangGraph proposed tools and compiles them into a ZK-Intent Graph."""
    print("\n[LangGraph Guard Node] Intercepting agent state memory matrix...")
    
    agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    session_key = "runtime_session_cryptographic_root_key_2026"
    
    # 2. Dispatch data vectors out-of-band to the hypervisor gate
    result = kernel_client.compile_and_authorize_intent(
        agent_id=agent_id,
        session_key=session_key,
        actions=state["proposed_actions"]
    )
    
    if result.get("success"):
        print(f"🎉 SECURE VERDICT: Firecracker simulation token acquired.")
        return {
            "validation_verdict": True,
            "simulation_token": result["simulation_token"],
            "execution_logs": "Kernel gate cleared."
        }
    else:
        print("❌ ABORT VERDICT: Core safety invariant violation detected.")
        return {
            "validation_verdict": False,
            "simulation_token": "",
            "execution_logs": f"Halt triggered: {result.get('error')}"
        }

def execution_router_edge(state: AgentState) -> str:
    """Evaluates the kernel verification matrix to route state execution threads."""
    if state["validation_verdict"]:
        return "commit_production_state"
    return "halt_and_mutate"

def commit_production_state_node(state: AgentState) -> Dict[str, Any]:
    print("[Infrastructure Engine] Applying signed state diffs to cloud clusters...")
    return {"execution_logs": "Production state updated successfully."}

def halt_and_mutate_node(state: AgentState) -> Dict[str, Any]:
    print("[STIM Engine] Purging context. Initiating moving target defense topology shuffle...")
    return {"execution_logs": "System network layout scrambled dynamically."}

# 3. Compile the Secured LangGraph State Machine Topology
workflow = StateGraph(AgentState)

# Add operational processing nodes
workflow.add_node("secops_fence", secops_kernel_fence_node)
workflow.add_node("commit_production_state", commit_production_state_node)
workflow.add_node("halt_and_mutate", halt_and_mutate_node)

# Map edge transitions using conditional router logic
workflow.set_entry_point("secops_fence")
workflow.add_conditional_edges(
    "secops_fence",
    execution_router_edge,
    {
        "commit_production_state": "commit_production_state",
        "halt_and_mutate": "halt_and_mutate"
    }
)
workflow.add_edge("commit_production_state", END)
workflow.add_edge("halt_and_mutate", END)

def execute_secure_graph():
    app = workflow.compile()
    initial_input = {
        "proposed_actions": [{
            "directive": "SYS_CALL_NETWORK_REDUCE",
            "target_urn": "urn:secops:aws:subnet-09f123"
        }],
        "validation_verdict": False,
        "simulation_token": "",
        "execution_logs": ""
    }
    print("[Initialization] Launching secure LangGraph multi-agent orchestration loop...")
    app.invoke(initial_input)

if __name__ == "__main__":
    execute_secure_graph()
