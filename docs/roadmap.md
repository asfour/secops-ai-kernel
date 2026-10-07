# SecOps Kernel: WebAssembly (Wasm) Sandboxing Roadmap

While our core Firecracker microVM snapshot framework provides complete OS-level isolation, it introduces an infrastructural constraint: it requires nested virtualization bare-metal hardware (`m6i.metal`) to execute out-of-band [deploy/aws-eks-deployment.md]. 

To broaden open-source adoption, our next major milestone is engineering an alternative, lightweight **WebAssembly Micro-Sandboxing Runtime Engine** using `Wasmtime` and `Wazero`.

## 🗺️ Execution Phases

### Phase 1: Wasm Guest Interface Core (Target: Q1)
* **Objective**: Compile high-privilege agent tools directly into standalone Wasm binary blocks (`.wasm`) using Rust or Go WebAssembly compiler targets.
* **Mechanism**: Expose a standard WebAssembly System Interface (WASI) mapping inside the kernel to securely pipe file metadata, network sockets, and execution environment strings straight into the isolated guest instance context.

### Phase 2: Wazero Runtime Integration (Target: Q2)
* **Objective**: Swap the nested microVM orchestration loops with an embedded, zero-dependency Go WebAssembly interpreter (`wazero`) running entirely within user-space.
* **Mechanism**: Instead of cloning an entire operating system kernel image layout, the runtime instantiates a sandboxed Wasm linear memory block (capped strictly at 128MB) inside a sub-millisecond thread execution window.

### Phase 3: Hybrid eBPF/Wasm State Verifier (Target: Q3)
* **Objective**: Merge WebAssembly linear memory drift metrics with our existing Ring-0 eBPF system call validation matrices [pkg/kernel/ebpf/monitor.c].
* **Mechanism**: The eBPF monitor traps host-level executions out-of-band while the Wasm engine restricts memory heap modifications internally. If code parameters drift from the pre-compiled `IntentGraph`, the runtime issues an instantaneous memory-page purge block.
