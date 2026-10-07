package firecracker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFile_CopiesContent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")

	if err := os.WriteFile(src, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing src fixture: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading dst: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("expected copied content 'hello', got %q", got)
	}
}

func TestCopyFile_MissingSourceErrors(t *testing.T) {
	dir := t.TempDir()
	if err := copyFile(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "dst")); err == nil {
		t.Fatal("expected an error for a missing source file")
	}
}
