package firecracker

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestDiffFiles_IdenticalFilesHaveZeroDrift(t *testing.T) {
	dir := t.TempDir()
	a := writeTempFile(t, dir, "a.mem", []byte("identical-guest-memory-content"))
	b := writeTempFile(t, dir, "b.mem", []byte("identical-guest-memory-content"))

	diff, err := diffFiles(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff != 0 {
		t.Fatalf("expected 0 drift bytes for identical files, got %d", diff)
	}
}

func TestDiffFiles_CountsDifferingBytes(t *testing.T) {
	dir := t.TempDir()
	a := writeTempFile(t, dir, "a.mem", []byte("aaaaaaaaaa"))
	b := writeTempFile(t, dir, "b.mem", []byte("aaaXXaaaaa"))

	diff, err := diffFiles(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff != 2 {
		t.Fatalf("expected 2 drift bytes, got %d", diff)
	}
}

func TestDiffFiles_DifferingLengthsCountTailAsDrift(t *testing.T) {
	dir := t.TempDir()
	a := writeTempFile(t, dir, "a.mem", []byte("short"))
	b := writeTempFile(t, dir, "b.mem", []byte("short-and-longer"))

	diff, err := diffFiles(a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff == 0 {
		t.Fatal("expected nonzero drift when file lengths differ")
	}
}

func TestDiffFiles_MissingFileErrors(t *testing.T) {
	dir := t.TempDir()
	a := writeTempFile(t, dir, "a.mem", []byte("x"))

	if _, err := diffFiles(a, filepath.Join(dir, "does-not-exist.mem")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
