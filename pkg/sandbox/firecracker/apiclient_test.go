package firecracker

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

// startFakeFirecrackerAPI spins up an HTTP server over a Unix socket,
// standing in for a real firecracker process's --api-sock. No real
// Firecracker binary or /dev/kvm access is available in CI/dev sandboxes,
// so this is how APIClient's request construction is verified: against a
// server that asserts exactly the paths/methods Firecracker's documented
// API expects.
func startFakeFirecrackerAPI(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "api.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening on fake unix socket: %v", err)
	}

	server := &http.Server{Handler: mux}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })

	return socketPath
}

func TestAPIClient_ConfiguresAndStartsGuest(t *testing.T) {
	seen := make(map[string]string) // path -> method
	mux := http.NewServeMux()
	record := func(path string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			seen[path] = r.Method
			w.WriteHeader(http.StatusNoContent)
		})
	}
	record("/boot-source")
	record("/drives/rootfs")
	record("/machine-config")
	record("/actions")
	record("/vm")
	record("/snapshot/create")

	socketPath := startFakeFirecrackerAPI(t, mux)
	client := NewAPIClient(socketPath)
	ctx := context.Background()

	if err := client.ConfigureMachine(ctx, 1, 512); err != nil {
		t.Fatalf("ConfigureMachine: %v", err)
	}
	if err := client.ConfigureBootSource(ctx, "/vmlinux", "console=ttyS0"); err != nil {
		t.Fatalf("ConfigureBootSource: %v", err)
	}
	if err := client.ConfigureRootDrive(ctx, "rootfs", "/rootfs.ext4"); err != nil {
		t.Fatalf("ConfigureRootDrive: %v", err)
	}
	if err := client.StartInstance(ctx); err != nil {
		t.Fatalf("StartInstance: %v", err)
	}
	if err := client.PauseVM(ctx); err != nil {
		t.Fatalf("PauseVM: %v", err)
	}
	if err := client.CreateSnapshot(ctx, "/snap.json", "/snap.mem"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if err := client.ResumeVM(ctx); err != nil {
		t.Fatalf("ResumeVM: %v", err)
	}

	wantMethods := map[string]string{
		"/boot-source":     http.MethodPut,
		"/drives/rootfs":   http.MethodPut,
		"/machine-config":  http.MethodPut,
		"/actions":         http.MethodPut,
		"/vm":              http.MethodPatch,
		"/snapshot/create": http.MethodPut,
	}
	for path, wantMethod := range wantMethods {
		gotMethod, ok := seen[path]
		if !ok {
			t.Fatalf("expected a request to %s, got none", path)
		}
		if gotMethod != wantMethod {
			t.Fatalf("%s: expected method %s, got %s", path, wantMethod, gotMethod)
		}
	}
}

func TestAPIClient_PropagatesHTTPErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/boot-source", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	socketPath := startFakeFirecrackerAPI(t, mux)

	client := NewAPIClient(socketPath)
	if err := client.ConfigureBootSource(context.Background(), "/vmlinux", ""); err == nil {
		t.Fatal("expected an error for a non-2xx response")
	}
}
