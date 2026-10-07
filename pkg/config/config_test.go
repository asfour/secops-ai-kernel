package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secops-kernel.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestLoad_RealRepoConfigParses(t *testing.T) {
	// configs/secops-kernel.yaml relative to this package's directory.
	cfg, err := Load("../../configs/secops-kernel.yaml")
	if err != nil {
		t.Fatalf("expected the real repo config to parse and validate, got: %v", err)
	}
	if cfg.Engine.MaxExecutionWindowMs != 500 {
		t.Fatalf("expected max_execution_window_ms 500, got %d", cfg.Engine.MaxExecutionWindowMs)
	}
	if cfg.Engine.MemoryFenceBytes != 536870912 {
		t.Fatalf("expected memory_fence_bytes 536870912, got %d", cfg.Engine.MemoryFenceBytes)
	}
	if cfg.Metadata.ClusterIdentity != "secops-isolated-core-01" {
		t.Fatalf("expected cluster_identity to parse, got %q", cfg.Metadata.ClusterIdentity)
	}
}

func TestLoad_MissingFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected an error for a nonexistent config path")
	}
}

func TestLoad_MalformedYAMLErrors(t *testing.T) {
	path := writeConfig(t, "not: [valid, yaml:\n  - indentation error")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoad_RejectsNonPositiveMaxExecutionWindow(t *testing.T) {
	path := writeConfig(t, `
engine:
  max_execution_window_ms: 0
  memory_fence_bytes: 536870912
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected a non-positive max_execution_window_ms to be rejected")
	}
}

func TestLoad_RejectsNonPositiveMemoryFence(t *testing.T) {
	path := writeConfig(t, `
engine:
  max_execution_window_ms: 500
  memory_fence_bytes: -1
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected a non-positive memory_fence_bytes to be rejected")
	}
}
