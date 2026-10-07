package server

import (
	"io"
	"testing"

	pb "secops-kernel/pkg/api/v2"

	"google.golang.org/grpc"
)

// fakeStreamSideChannelStream implements pb.TelemetryStreamer_StreamSideChannelServer
// (grpc.ClientStreamingServer[pb.TelemetryFrame, pb.TelemetryAcknowledgement])
// by replaying a fixed slice of frames through Recv, then io.EOF.
type fakeStreamSideChannelStream struct {
	grpc.ServerStream
	frames []*pb.TelemetryFrame
	next   int
	acked  *pb.TelemetryAcknowledgement
}

func (f *fakeStreamSideChannelStream) Recv() (*pb.TelemetryFrame, error) {
	if f.next >= len(f.frames) {
		return nil, io.EOF
	}
	frame := f.frames[f.next]
	f.next++
	return frame, nil
}

func (f *fakeStreamSideChannelStream) SendAndClose(ack *pb.TelemetryAcknowledgement) error {
	f.acked = ack
	return nil
}

func TestStreamSideChannel_AcknowledgesLastSequenceOnEOF(t *testing.T) {
	s := NewTelemetryServer()
	stream := &fakeStreamSideChannelStream{
		frames: []*pb.TelemetryFrame{
			{SequenceId: 1, AgentId: "agent-1"},
			{SequenceId: 2, AgentId: "agent-1"},
			{SequenceId: 3, AgentId: "agent-1"},
		},
	}

	if err := s.StreamSideChannel(stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stream.acked == nil {
		t.Fatal("expected an acknowledgement to be sent")
	}
	if stream.acked.ReceivedSequenceId != 3 {
		t.Fatalf("expected ReceivedSequenceId 3, got %d", stream.acked.ReceivedSequenceId)
	}
	if !stream.acked.ProcessingStable {
		t.Fatal("expected ProcessingStable to be true")
	}
}

func TestStreamSideChannel_EmptyStreamAcksZero(t *testing.T) {
	s := NewTelemetryServer()
	stream := &fakeStreamSideChannelStream{}

	if err := s.StreamSideChannel(stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stream.acked.ReceivedSequenceId != 0 {
		t.Fatalf("expected ReceivedSequenceId 0 for an empty stream, got %d", stream.acked.ReceivedSequenceId)
	}
}
