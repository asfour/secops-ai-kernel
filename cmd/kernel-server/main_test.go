package main

import (
	"os"
	"path/filepath"
	"testing"

	"secops-kernel/pkg/config"
)

func TestLoadTokenController_MissingFileReturnsError(t *testing.T) {
	_, err := loadTokenController(filepath.Join(t.TempDir(), "does-not-exist.o"))
	if err == nil {
		t.Fatal("expected an error for a nonexistent object path")
	}
}

func TestLoadTokenController_InvalidELFReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-bpf-object.o")
	if err := os.WriteFile(path, []byte("not an ELF file"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := loadTokenController(path); err == nil {
		t.Fatal("expected an error for a file that isn't a valid BPF ELF object")
	}
}

func TestBuildTokenGranter_MissingObjectAndEnforceTrue_Errors(t *testing.T) {
	objectPath := filepath.Join(t.TempDir(), "does-not-exist.o")
	if _, err := buildTokenGranter(objectPath, true); err == nil {
		t.Fatal("expected an error when enforceEBPF=true and the object can't be loaded")
	}
}

func TestBuildTokenGranter_MissingObjectAndEnforceFalse_ReturnsNilGranterNoError(t *testing.T) {
	objectPath := filepath.Join(t.TempDir(), "does-not-exist.o")
	tokens, err := buildTokenGranter(objectPath, false)
	if err != nil {
		t.Fatalf("expected no error when enforceEBPF=false, got: %v", err)
	}
	if tokens != nil {
		t.Fatal("expected a true nil TokenGranter interface value, not a typed-nil wrapper")
	}
}

func TestCheckNetworkFenceCapability_EnforceFalseNeverErrors(t *testing.T) {
	// Whether or not this host can actually create a tap+nftables fence,
	// enforceNetworkFence=false must never return an error — only
	// enforceNetworkFence=true can turn an unavailable capability into a
	// fatal startup error.
	if _, err := checkNetworkFenceCapability(false); err != nil {
		t.Fatalf("expected no error with enforceNetworkFence=false, got: %v", err)
	}
}

func TestNewGRPCServer_RegistersAllThreeServices(t *testing.T) {
	cfg := &config.Config{}
	cfg.Engine.MaxExecutionWindowMs = 500
	cfg.Engine.MemoryFenceBytes = 512 * 1024 * 1024

	grpcServer := newGRPCServer(nil, false, cfg, "/kernel", "/rootfs")

	info := grpcServer.GetServiceInfo()
	for _, name := range []string{
		"secops.kernel.v2.ZKIntentCompiler",
		"secops.kernel.v2.ForkVerifyEngine",
		"secops.kernel.v2.TelemetryStreamer",
	} {
		if _, ok := info[name]; !ok {
			t.Errorf("expected service %q to be registered, got services: %v", name, info)
		}
	}
}
