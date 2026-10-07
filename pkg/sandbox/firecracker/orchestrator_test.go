package firecracker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForSocket_ReturnsOnceFileAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte{}, 0o600)
	}()

	if err := waitForSocket(context.Background(), path, time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForSocket_TimesOutIfNeverCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-appears.sock")

	if err := waitForSocket(context.Background(), path, 50*time.Millisecond); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestWaitForSocket_RespectsContextCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-appears.sock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitForSocket(ctx, path, time.Second); err == nil {
		t.Fatal("expected context cancellation to produce an error")
	}
}
