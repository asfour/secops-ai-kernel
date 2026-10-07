import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Ensure local path references align cleanly
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# crewai_bridge instantiates SecOpsKernelClient at import time, which now
# requires either mTLS certs or an explicit insecure opt-in (see
# docs/improvement_spec.md item #7). This test suite mocks the client
# entirely, so an unauthenticated channel is acceptable here.
os.environ.setdefault("SECOPS_ALLOW_INSECURE_KERNEL_CLIENT", "true")
import crewai_bridge

class TestCrewAIIntegrationBridge(unittest.TestCase):
    """Automated unit verification for the CrewAI secure tool interception mechanics."""

    @patch('client.SecOpsKernelClient')
    def test_secure_tool_interception_pass_verdict(self, mock_client_class):
        """Verify the tool call maps cleanly and parses an active approval token loop."""
        # 1. Arrange a mock successful return state matching structural kernel formats
        mock_instance = MagicMock()
        mock_instance.compile_and_authorize_intent.return_value = {
            "success": True,
            "simulation_token": "st_test_mock_token_99182",
            "verdict": 1
        }
        mock_client_class.return_value = mock_instance
        
        # Override the global active client inside the module for deterministic testing
        crewai_bridge.kernel_client = mock_instance

        # 2. Act: Trigger the tool function logic
        test_subnet = "subnet-09f123"
        execution_output = crewai_bridge.secure_network_mitigation_tool._run(target_subnet=test_subnet)

        # 3. Assert: Verify the parameters matched exactly and returned an approved token trace
        mock_instance.compile_and_authorize_intent.assert_called_once_with(
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "runtime_session_cryptographic_root_key_2026",
            [{
                "directive": "SYS_CALL_NETWORK_REDUCE",
                "target_urn": f"urn:secops:aws:{test_subnet}",
                "payload": test_subnet.encode('utf-8')
            }]
        )
        self.assertIn("Execution Block Approved", execution_output)
        self.assertIn("st_test_mock_token_99182", execution_output)

    @patch('client.SecOpsKernelClient')
    def test_secure_tool_interception_fail_verdict(self, mock_client_class):
        """Verify the framework catches structural invariant rejections gracefully."""
        mock_instance = MagicMock()
        mock_instance.compile_and_authorize_intent.return_value = {
            "success": False,
            "error": "0x00_INVARIANTS_VIOLATION_BLAST_RADIUS_EXCEEDED"
        }
        mock_client_class.return_value = mock_instance
        crewai_bridge.kernel_client = mock_instance

        execution_output = crewai_bridge.secure_network_mitigation_tool._run(target_subnet="subnet-malicious-range")

        self.assertIn("CRITICAL HALT", execution_output)
        self.assertIn("0x00_INVARIANTS_VIOLATION_BLAST_RADIUS_EXCEEDED", execution_output)

if __name__ == "__main__":
    unittest.main()
