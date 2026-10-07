package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// APIClient talks to a running firecracker process's REST API, exposed
// over a Unix domain socket (the same --api-sock path SpawnIsolatedStateMirror
// passes to the firecracker binary). Only the subset of Firecracker's
// documented API this package needs is implemented: machine/boot-source/
// drive configuration to boot a guest, instance start, and the pause ->
// snapshot/create -> resume sequence used to capture guest memory for
// diffing (see IMPROVEMENT_SPEC.md item #6).
type APIClient struct {
	httpClient *http.Client
}

func NewAPIClient(socketPath string) *APIClient {
	return &APIClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

func (c *APIClient) do(ctx context.Context, method, path string, body interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return fmt.Errorf("encoding request body for %s %s: %w", method, path, err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, &buf)
	if err != nil {
		return fmt.Errorf("building request %s %s: %w", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: unexpected status %d", method, path, resp.StatusCode)
	}
	return nil
}

func (c *APIClient) ConfigureBootSource(ctx context.Context, kernelImagePath, bootArgs string) error {
	return c.do(ctx, http.MethodPut, "/boot-source", map[string]string{
		"kernel_image_path": kernelImagePath,
		"boot_args":         bootArgs,
	})
}

func (c *APIClient) ConfigureRootDrive(ctx context.Context, driveID, pathOnHost string) error {
	return c.do(ctx, http.MethodPut, "/drives/"+driveID, map[string]interface{}{
		"drive_id":       driveID,
		"path_on_host":   pathOnHost,
		"is_root_device": true,
		"is_read_only":   false,
	})
}

func (c *APIClient) ConfigureMachine(ctx context.Context, vcpuCount, memSizeMib int64) error {
	return c.do(ctx, http.MethodPut, "/machine-config", map[string]interface{}{
		"vcpu_count":   vcpuCount,
		"mem_size_mib": memSizeMib,
	})
}

func (c *APIClient) StartInstance(ctx context.Context) error {
	return c.do(ctx, http.MethodPut, "/actions", map[string]string{
		"action_type": "InstanceStart",
	})
}

func (c *APIClient) PauseVM(ctx context.Context) error {
	return c.do(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"})
}

func (c *APIClient) ResumeVM(ctx context.Context) error {
	return c.do(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"})
}

// CreateSnapshot requires the VM to be in the Paused state; callers must
// bracket this with PauseVM/ResumeVM.
func (c *APIClient) CreateSnapshot(ctx context.Context, snapshotPath, memFilePath string) error {
	return c.do(ctx, http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_path": snapshotPath,
		"mem_file_path": memFilePath,
	})
}
