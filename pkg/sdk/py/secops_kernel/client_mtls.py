"""Deprecated: SecOpsKernelClient (client.py) now enforces mTLS by default.

SecOpsKernelSecureClient is kept only so existing imports of this module
keep working; it is now a thin subclass instead of a second copy of the
channel/credential-loading logic.
"""
from client import SecOpsKernelClient


class SecOpsKernelSecureClient(SecOpsKernelClient):
    """Enterprise-grade Asymmetric mTLS Client SDK for SecOps Kernel OS."""

    def __init__(
        self,
        target_address: str,
        server_ca_cert_path: str,
        client_key_path: str,
        client_cert_path: str
    ):
        super().__init__(
            target_address=target_address,
            server_ca_cert_path=server_ca_cert_path,
            client_key_path=client_key_path,
            client_cert_path=client_cert_path,
        )
