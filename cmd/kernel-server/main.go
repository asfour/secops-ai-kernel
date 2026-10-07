// Command kernel-server hosts the ZKIntentCompiler, ForkVerifyEngine, and
// TelemetryStreamer gRPC services described in pkg/api/v2/secops_kernel.proto.
//
// Previously no process implemented these services at all: clients like
// pkg/agent/remediation_worker.go dialed 127.0.0.1:50051 against nothing.
// See IMPROVEMENT_SPEC.md item #2.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/config"
	"secops-kernel/pkg/kernel/ebpftoken"
	"secops-kernel/pkg/sandbox/firecracker"
	"secops-kernel/pkg/server"

	"google.golang.org/grpc"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:50051", "gRPC listen address")
	configPath := flag.String("config", "configs/secops-kernel.yaml", "runtime policy config path")
	kernelPath := flag.String("kernel-path", "/var/lib/secops-kernel/vmlinux.bin", "Firecracker guest kernel image")
	rootfsPath := flag.String("rootfs-path", "/var/lib/secops-kernel/rootfs.ext4", "Firecracker guest rootfs image")
	bpfObjectPath := flag.String("bpf-object", "pkg/kernel/ebpf/monitor.o", "compiled eBPF monitor object")
	enforceEBPF := flag.Bool("enforce-ebpf", true, "require a working eBPF token controller to start (refuse to run unenforced)")
	enforceNetworkFence := flag.Bool("enforce-network-fence", true, "require working tap+nftables network fencing to start (refuse to run unenforced)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config %q: %v", *configPath, err)
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listenAddr, err)
	}

	tokens, err := buildTokenGranter(*bpfObjectPath, *enforceEBPF)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if tokens != nil {
		log.Printf("eBPF token enforcement active (object=%s)", *bpfObjectPath)
	} else {
		log.Printf("WARNING: running WITHOUT eBPF execution-token enforcement")
	}

	networkFenceOK, err := checkNetworkFenceCapability(*enforceNetworkFence)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if networkFenceOK {
		log.Printf("network fence capability verified (tap+nftables)")
	} else {
		log.Printf("WARNING: running WITHOUT network-fence enforcement")
	}

	grpcServer := newGRPCServer(tokens, networkFenceOK, cfg, *kernelPath, *rootfsPath)

	log.Printf("kernel-server listening on %s", *listenAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("grpc serve error: %v", err)
	}
}

// newGRPCServer wires the compiler, orchestrator, fork-verify, and
// telemetry services together and registers them on a fresh grpc.Server.
// Separated from main's flag parsing and net.Listen/Serve so it can be
// tested without binding a real socket or running forever.
func newGRPCServer(tokens firecracker.TokenGranter, enforceNetworkFence bool, cfg *config.Config, kernelPath, rootfsPath string) *grpc.Server {
	maxExecutionWindow := time.Duration(cfg.Engine.MaxExecutionWindowMs) * time.Millisecond
	memoryLimitMB := cfg.Engine.MemoryFenceBytes / (1024 * 1024)

	compiler := server.NewCompilerServerWithCeiling(maxExecutionWindow)
	orchestrator := firecracker.NewOrchestrator(tokens)
	orchestrator.EnforceNetworkFence = enforceNetworkFence
	forkVerify := server.NewForkVerifyServer(compiler, orchestrator, kernelPath, rootfsPath, memoryLimitMB)
	telemetry := server.NewTelemetryServer()

	grpcServer := grpc.NewServer()
	pb.RegisterZKIntentCompilerServer(grpcServer, compiler)
	pb.RegisterForkVerifyEngineServer(grpcServer, forkVerify)
	pb.RegisterTelemetryStreamerServer(grpcServer, telemetry)
	return grpcServer
}

// buildTokenGranter loads and attaches the eBPF token controller. A nil
// *ebpftoken.Controller is deliberately never assigned to the returned
// firecracker.TokenGranter interface value (see the comment on that
// interface): on any failure this returns a true nil interface, or a
// non-nil error if enforceEBPF is true.
func buildTokenGranter(objectPath string, enforceEBPF bool) (firecracker.TokenGranter, error) {
	ctrl, err := loadTokenController(objectPath)
	if err != nil {
		if enforceEBPF {
			return nil, fmt.Errorf("eBPF token controller unavailable and -enforce-ebpf=true: %w\n"+
				"(run with -enforce-ebpf=false only for local development without kernel enforcement)", err)
		}
		return nil, nil
	}
	if _, err := ctrl.Attach(); err != nil {
		return nil, fmt.Errorf("loaded eBPF object but failed to attach tracepoint: %w", err)
	}
	return ctrl, nil
}

// checkNetworkFenceCapability probes whether this host can actually create
// a tap device + nftables table (requires CAP_NET_ADMIN). The returned
// bool is what Orchestrator.EnforceNetworkFence should be set to: true
// means the capability was verified; false means it wasn't, which is
// only returned (rather than an error) when enforceNetworkFence is false.
func checkNetworkFenceCapability(enforceNetworkFence bool) (bool, error) {
	if err := firecracker.ProbeCapability(); err != nil {
		if enforceNetworkFence {
			return false, fmt.Errorf("network fence capability unavailable and -enforce-network-fence=true: %w\n"+
				"(run with -enforce-network-fence=false only for local development without network enforcement)", err)
		}
		return false, nil
	}
	return true, nil
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
