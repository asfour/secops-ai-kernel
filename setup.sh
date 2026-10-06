#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "⚙️  Initializing SecOps Kernel Machine Target Host Environment..."
echo "================================================================="

# 1. Update Core System Dev Dependencies
sudo apt-get update -y
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    protobuf-compiler \
    golang-go \
    curl \
    iproute2 \
    z3

# 2. Grab and Deploy Firecracker Hypervisor MicroVM Binary
FC_VERSION="v1.7.0"
ARCH="$(uname -m)"
echo "Downloading Firecracker (${FC_VERSION}) for ${ARCH}..."
curl -sSLo firecracker "https://github.com{FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}"
chmod +x firecracker
sudo mv firecracker /usr/local/bin/firecracker

# 3. Mount and Verify Low-Level Virtualization Enclaves
if [ ! -c /dev/kvm ]; then
    echo "🚨 ERROR: /dev/kvm is not accessible. Hardware-level nested acceleration is required."
    exit 1
fi
sudo chmod a+rw /dev/kvm

# 4. Handle Go Module Initialization Loops Programmatically
if [ ! -f go.mod ]; then
    echo "Initializing fresh Go module layout workspace..."
    go mod init secops-kernel
fi

echo "Synchronizing module dependencies..."
go get google.golang.org/grpc
go get google.golang.org/protobuf
go mod tidy

# 5. Generate Programmatic gRPC Enclaves and Stubs
echo "Compiling Pure Machine Protobuf Core buffers..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

export GOPATH="$(go env GOPATH)"
export PATH="$PATH:$GOPATH/bin"

protoc -I=pkg/api/v2/ \
  --go_out=paths=source_relative:pkg/api/v2/ \
  --go-grpc_out=paths=source_relative:pkg/api/v2/ \
  pkg/api/v2/secops_kernel.proto

# 6. Compile Ring-0 Kernel Monitor via Clang Bytecode BPF Toolchain
echo "Building Ring-0 System Call Interception Blocks (eBPF)..."
clang -O2 -target bpf -c pkg/kernel/ebpf/monitor.c -o pkg/kernel/ebpf/monitor.o

echo "================================================================="
echo "✅ SecOps Kernel v2.0 Setup Complete. Ready for Headless Ingestion."
echo "================================================================="
