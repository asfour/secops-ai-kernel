#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "🔐 SecOps Kernel PKI: Provisioning Cryptographic mTLS Certificates..."
echo "================================================================="

# 1. Establish an isolated output directory workspace
mkdir -p secrets && cd secrets

# 2. Generate the Root Certificate Authority (CA) Material
openssl ecparam -name prime256v1 -genkey -noout -out secops_ca.key
openssl req -new -x509 -sha256 -key secops_ca.key -days 365 \
  -subj "/CN=SecOps Kernel Root CA/O=SecOps Kernel/OU=Security Operations" \
  -out secops_ca.crt

# 3. Generate and Sign the Server Certificate Enclave
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key \
  -subj "/CN=kernel-core/O=SecOps Kernel/OU=Core Runtime Enclave" \
  -out server.csr
openssl x509 -req -sha256 -in server.csr -CA secops_ca.crt -CAkey secops_ca.key \
  -CAcreateserial -days 365 -out server.crt

# 4. Generate and Sign the Programmatic Agent Client SDK Certificate
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key \
  -subj "/CN=autonomous-agent-worker/O=SecOps Agent Matrix/OU=High Privilege Tooling" \
  -out client.csr
openssl x509 -req -sha256 -in client.csr -CA secops_ca.crt -CAkey secops_ca.key \
  -CAcreateserial -days 365 -out client.crt

# 5. Restrict file permissions according to the Principle of Least Privilege
chmod 600 *.key
chmod 644 *.crt

echo "================================================================="
echo "✅ PKI Certificates successfully mapped into /secrets/ directory."
echo "================================================================="
