// Package config loads configs/secops-kernel.yaml.
//
// Previously nothing in this repository read this file at all — it
// documented intended runtime policy (timeouts, memory limits, fail-safe
// modes) that no running code enforced. Load parses it into a typed
// Config; cmd/kernel-server wires two fields into real enforcement
// (Engine.MaxExecutionWindowMs as a ceiling on a request's requested
// execution window, Engine.MemoryFenceBytes as the default microVM
// memory limit). Every other field is parsed and validated for shape,
// but not yet wired to any behavior — see the field comments below for
// which ones those are.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version  string `yaml:"version"`
	Metadata struct {
		ClusterIdentity        string `yaml:"cluster_identity"`
		SecurityClearanceFloor string `yaml:"security_clearance_floor"`
	} `yaml:"metadata"`

	Engine struct {
		Runtime string `yaml:"runtime"`

		// MaxExecutionWindowMs is enforced: cmd/kernel-server rejects any
		// CompileZKIntentRequest whose max_allowed_latency_ms exceeds it.
		MaxExecutionWindowMs int64 `yaml:"max_execution_window_ms"`

		// MemoryFenceBytes is enforced: used as the default microVM memory
		// limit (converted to MB) in pkg/server.ForkVerifyServer.
		MemoryFenceBytes int64 `yaml:"memory_fence_bytes"`
	} `yaml:"engine"`

	// TaintTracking is parsed but not yet enforced by any code path.
	TaintTracking struct {
		PropagateLLMOutputs bool     `yaml:"propagate_llm_outputs"`
		EnforcedModes       []string `yaml:"enforced_modes"`
	} `yaml:"taint_tracking"`

	// Cryptography is parsed but not yet enforced: TokenTTLMs is not the
	// same thing as the per-request eBPF token TTL (which is derived from
	// the request's own max_allowed_latency_ms, see
	// pkg/sandbox/firecracker.Orchestrator.waitForExecStopAndGrantToken),
	// AttestationMode and ZKCircuitPath describe hardware attestation and
	// a real ZK circuit that do not exist in this codebase yet.
	Cryptography struct {
		TokenTTLMs      int64  `yaml:"token_ttl_ms"`
		AttestationMode string `yaml:"attestation_mode"`
		ZKCircuitPath   string `yaml:"zk_circuit_path"`
	} `yaml:"cryptography"`

	// FailSafe is parsed but not yet enforced: there is currently a
	// single abort path (VERDICT_0x00_ABORT), not a distinct behavior for
	// OnNonDeterminism vs OnTimeout, and TelemetryStream is not dialed by
	// anything.
	FailSafe struct {
		OnNonDeterminism string `yaml:"on_non_determinism"`
		OnTimeout        string `yaml:"on_timeout"`
		TelemetryStream  string `yaml:"telemetry_stream"`
	} `yaml:"fail_safe"`
}

// Load reads and parses path, failing closed (a non-nil error) rather
// than falling back to defaults if the file is missing, malformed, or
// specifies a non-positive value for either field cmd/kernel-server
// actually enforces.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if cfg.Engine.MaxExecutionWindowMs <= 0 {
		return nil, fmt.Errorf("config %q: engine.max_execution_window_ms must be positive, got %d", path, cfg.Engine.MaxExecutionWindowMs)
	}
	if cfg.Engine.MemoryFenceBytes <= 0 {
		return nil, fmt.Errorf("config %q: engine.memory_fence_bytes must be positive, got %d", path, cfg.Engine.MemoryFenceBytes)
	}

	return &cfg, nil
}
