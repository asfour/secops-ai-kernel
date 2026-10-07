package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyKVMAccess_ExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	ok, message := verifyKVMAccess(path)
	if !ok {
		t.Fatal("expected ok=true for an existing path")
	}
	if message == "" {
		t.Fatal("expected a non-empty message")
	}
}

func TestVerifyKVMAccess_MissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")

	ok, message := verifyKVMAccess(path)
	if ok {
		t.Fatal("expected ok=false for a missing path")
	}
	if message == "" {
		t.Fatal("expected a non-empty message")
	}
}

func TestPrintUsage_DoesNotPanic(t *testing.T) {
	printUsage()
}
