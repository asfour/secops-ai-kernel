package server

import (
	"io"
	"log"

	pb "secops-kernel/pkg/api/v2"
)

// TelemetryServer implements pb.TelemetryStreamerServer, accepting the
// client-streamed side-channel frames described in
// pkg/api/v2/secops_kernel.proto and acknowledging the last sequence seen.
type TelemetryServer struct {
	pb.UnimplementedTelemetryStreamerServer
}

func NewTelemetryServer() *TelemetryServer {
	return &TelemetryServer{}
}

func (s *TelemetryServer) StreamSideChannel(stream pb.TelemetryStreamer_StreamSideChannelServer) error {
	var lastSeq uint64
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.TelemetryAcknowledgement{
				ReceivedSequenceId: lastSeq,
				ProcessingStable:   true,
			})
		}
		if err != nil {
			return err
		}
		lastSeq = frame.GetSequenceId()
		log.Printf("telemetry: agent=%s microvm=%s seq=%d cpu_instr=%d cache_miss=%d",
			frame.GetAgentId(), frame.GetActiveMicrovmId(), frame.GetSequenceId(),
			frame.GetCpuInstructionCount(), frame.GetCacheMissDelta())
	}
}
