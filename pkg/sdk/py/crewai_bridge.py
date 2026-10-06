import os
import sys
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from langchain.tools import tool

# Ensure local SDK pathway mapping is active
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from client import SecOpsKernelClient

# 1. Initialize the Secure Kernel SDK connection
# Points to our docker mesh kernel-core endpoint
KERNEL_ADDRESS = os.getenv("SECOPS_KERNEL_ADDRESS", "127.0.0.1:50051")
kernel_client = SecOpsKernelClient(target_address=KERNEL_ADDRESS)

@tool("Secure Network Mitigation Tool")
def secure_network_mitigation_tool(target_subnet: str) -> str:
    """Useful to isolate subnets during an ongoing active intrusion or breach."""
    print(f"\n[CrewAI Tool Triggered] Proposed Action: Isolate Subnet {target_subnet}")
    
    agent_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    session_key = "runtime_session_cryptographic_root_key_2026"
    
    # 2. Package the CrewAI action block and dispatch to the hypervisor gate
    actions = [
        {
            "directive": "SYS_CALL_NETWORK_REDUCE",
            "target_urn": f"urn:secops:aws:{target_subnet}",
            "payload": target_subnet.encode('utf-8')
        }
    ]
    
    print("[SDK Intercept] Compiling action into ZK-Intent Graph...")
    result = kernel_client.compile_and_authorize_intent(agent_id, session_key, actions)
    
    if result.get("success"):
        return f"Execution Block Approved. Token assigned: {result['simulation_token']}. Committing state diff safely."
    else:
        return f"CRITICAL HALT: SecOps Kernel rejected the action graph. Error: {result.get('error', 'Invariants Voilation')}."

# 3. Define the Autonomous Incident Responder Crew
incident_agent = Agent(
    role="Automated Core DevSecOps Responder",
    goal="Isolate compromised cluster subnets immediately when zero-day vector metrics skew.",
    backstory="An autonomous machine worker running with restricted infrastructure write privileges.",
    tools=[secure_network_mitigation_tool],
    verbose=True,
    memory=False
)

mitigation_task = Task(
    description="Analyze active security threat signatures and execute the isolation tool for subnet-09f123.",
    expected_output="Cryptographic confirmation token verifying state validation from the underlying kernel hypervisor.",
    agent=incident_agent
)

def run_secure_agent_workflow():
    secops_crew = Crew(
        agents=[incident_agent],
        tasks=[mitigation_task],
        process=Process.sequential
    )
    print("\n[System Initialization] Starting CrewAI autonomous execution workflow...")
    secops_crew.kickoff()

if __name__ == "__main__":
    run_secure_agent_workflow()
