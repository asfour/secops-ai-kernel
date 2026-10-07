package server

import (
	"testing"

	pb "secops-kernel/pkg/api/v2"
	"secops-kernel/pkg/sandbox/firecracker"

	"google.golang.org/grpc"
)

// fakeExecuteForkVerifyStream implements pb.ForkVerifyEngine_ExecuteForkVerifyServer
// (grpc.ServerStreamingServer[pb.ForkVerifyResponse]) just enough to drive
// ExecuteForkVerify's early "token not found" branch, which never touches
// anything from the embedded nil grpc.ServerStream beyond what's overridden
// here.
type fakeExecuteForkVerifyStream struct {
	grpc.ServerStream
	sent *pb.ForkVerifyResponse
}

func (f *fakeExecuteForkVerifyStream) Send(resp *pb.ForkVerifyResponse) error {
	f.sent = resp
	return nil
}

func TestExecuteForkVerify_AbortsOnUnknownToken(t *testing.T) {
	compiler := NewCompilerServer()
	orchestrator := firecracker.NewOrchestrator(nil)
	s := NewForkVerifyServer(compiler, orchestrator, "/kernel", "/rootfs", 512)

	stream := &fakeExecuteForkVerifyStream{}
	err := s.ExecuteForkVerify(&pb.ForkVerifyRequest{SimulationToken: "st_does_not_exist"}, stream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stream.sent == nil {
		t.Fatal("expected a response to be sent")
	}
	if stream.sent.Verdict != pb.ExecutionVerdict_VERDICT_0x00_ABORT {
		t.Fatalf("expected ABORT for an unknown simulation token, got %v", stream.sent.Verdict)
	}
}
