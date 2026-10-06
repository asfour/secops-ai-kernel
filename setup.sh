#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "⚙️  Initializing SecOps Kernel Machine Target Host Environment..."
echo "================================================================="

sudo apt-get update -y
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    protobuf-compiler \
    golang-go \
    curl \
    iproute2

FC_VERSION="v1.7.0"
ARCH="$(uname -m)"
echo "Downloading Firecracker (${FC_VERSION}) for ${ARCH}..."
curl -sSLo firecracker "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}"
chmod +x firecracker
sudo mv firecracker /usr/local/bin/firecracker

if [ ! -c /dev/kvm ]; then
    echo "🚨 ERROR: /dev/kvm is not accessible. Hardware-level nested acceleration is required."
    exit 1
fi
sudo chmod +x /dev/kvm

# Locate Step 4 inside setup.sh and make sure it matches this explicit declaration:
echo "Compiling Pure Machine Protobuf Core buffers..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Add these lines to explicitly hook the environment profile variables
export GOPATH="$(go env GOPATH)"
export PATH="$PATH:$GOPATH/bin"

protoc -I=pkg/api/v2/ \
  --go_out=paths=source_relative:pkg/api/v2/ \
  --go-grpc_out=paths=source_relative:pkg/api/v2/ \
  pkg/api/v2/secops_kernel.proto

echo "Building Ring-0 System Call Interception Blocks (eBPF)..."
clang -O2 -target bpf -c pkg/kernel/ebpf/monitor.c -o pkg/kernel/ebpf/monitor.o

echo "================================================================="
echo "✅ SecOps Kernel v2.0 Setup Complete. Ready for Headless Ingestion."
echo "================================================================="
