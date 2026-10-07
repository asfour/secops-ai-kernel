package ebpftoken

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests cover Load()'s error paths only. Exercising the happy path
// (loading pkg/kernel/ebpf/monitor.o, attaching it, and granting/revoking a
// real token) requires a clang-compiled BPF object and CAP_BPF/CAP_SYS_ADMIN
// to actually load it into the kernel — neither is available in the dev
// sandbox or CI environment this was written in. See IMPROVEMENT_SPEC.md
// item #9.

func TestLoad_MissingFileReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.o"))
	if err == nil {
		t.Fatal("expected an error for a nonexistent object path")
	}
}

func TestLoad_InvalidELFReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-bpf-object.o")
	if err := os.WriteFile(path, []byte("this is not an ELF file"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for a file that isn't a valid BPF ELF object")
	}
}
