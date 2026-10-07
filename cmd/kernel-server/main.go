// Command kernel-server hosts the ZKIntentCompiler, ForkVerifyEngine, and
// TelemetryStreamer gRPC services described in pkg/api/v2/secops_kernel.proto.
//
// Previously no process implemented these services at all: clients like
// pkg/agent/remediation_worker.go dialed 127.0.0.1:50051 against nothing.
// See IMPROVEMENT_SPEC.md item #2.
package main

import (
	"flag"
	"log"
	"net"
	"os"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/kernel/ebpftoken"
	"secops-kernel/pkg/sandbox/firecracker"
	"secops-kernel/pkg/server"

	"google.golang.org/grpc"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:50051", "gRPC listen address")
	kernelPath := flag.String("kernel-path", "/var/lib/secops-kernel/vmlinux.bin", "Firecracker guest kernel image")
	rootfsPath := flag.String("rootfs-path", "/var/lib/secops-kernel/rootfs.ext4", "Firecracker guest rootfs image")
	bpfObjectPath := flag.String("bpf-object", "pkg/kernel/ebpf/monitor.o", "compiled eBPF monitor object")
	enforceEBPF := flag.Bool("enforce-ebpf", true, "require a working eBPF token controller to start (refuse to run unenforced)")
	flag.Parse()

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listenAddr, err)
	}

	// tokens is declared as the interface type (not *ebpftoken.Controller)
	// and left at its zero value on failure. Assigning a typed-nil
	// *ebpftoken.Controller to this interface instead would produce a
	// non-nil interface wrapping a nil pointer — firecracker.Orchestrator's
	// `o.Tokens != nil` check would then incorrectly report "enforcement
	// enabled" and panic on first use.
	var tokens firecracker.TokenGranter
	ctrl, err := loadTokenController(*bpfObjectPath)
	if err != nil {
		if *enforceEBPF {
			log.Fatalf("eBPF token controller unavailable and -enforce-ebpf=true: %v\n"+
				"(run with -enforce-ebpf=false only for local development without kernel enforcement)", err)
		}
		log.Printf("WARNING: running WITHOUT eBPF execution-token enforcement: %v", err)
	} else {
		if _, err := ctrl.Attach(); err != nil {
			log.Fatalf("loaded eBPF object but failed to attach tracepoint: %v", err)
		}
		tokens = ctrl
		log.Printf("eBPF token enforcement active (object=%s)", *bpfObjectPath)
	}

	compiler := server.NewCompilerServer()
	orchestrator := firecracker.NewOrchestrator(tokens)
	forkVerify := server.NewForkVerifyServer(compiler, orchestrator, *kernelPath, *rootfsPath)
	telemetry := server.NewTelemetryServer()

	grpcServer := grpc.NewServer()
	pb.RegisterZKIntentCompilerServer(grpcServer, compiler)
	pb.RegisterForkVerifyEngineServer(grpcServer, forkVerify)
	pb.RegisterTelemetryStreamerServer(grpcServer, telemetry)

	log.Printf("kernel-server listening on %s", *listenAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("grpc serve error: %v", err)
	}
}

// loadTokenController returns a non-nil *ebpftoken.Controller only if the
// compiled BPF object can actually be loaded (requires CAP_BPF/CAP_SYS_ADMIN
// and a compiled pkg/kernel/ebpf/monitor.o — see setup.sh). It deliberately
// returns a typed nil (via the interface boundary in firecracker.TokenGranter)
// rather than panicking, so operators can explicitly opt out with
// -enforce-ebpf=false in environments that can't load BPF programs
// (e.g. containers without CAP_BPF, CI runners, developer laptops).
func loadTokenController(objectPath string) (*ebpftoken.Controller, error) {
	if _, err := os.Stat(objectPath); err != nil {
		return nil, err
	}
	return ebpftoken.Load(objectPath)
}
