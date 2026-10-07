package firecracker

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireE2fsprogs skips the test if mkfs.ext4/debugfs aren't on PATH,
// rather than failing CI environments that might lack e2fsprogs. Both are
// present in this project's own setup.sh dependency list and are standard
// on Debian/Ubuntu, so skips are not expected in practice.
func requireE2fsprogs(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"mkfs.ext4", "debugfs"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found on PATH, skipping", bin)
		}
	}
}

// makeExt4Image creates an empty ext4 image of sizeMB at path.
func makeExt4Image(t *testing.T, path string, sizeMB int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating image file: %v", err)
	}
	if err := f.Truncate(int64(sizeMB) * 1024 * 1024); err != nil {
		t.Fatalf("truncating image file: %v", err)
	}
	f.Close()

	cmd := exec.Command("mkfs.ext4", "-F", "-q", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v (%s)", err, out)
	}
}

// debugfsWrite copies hostContent into the image at guestPath using
// debugfs's unprivileged write-mode commands (no mount required).
func debugfsWrite(t *testing.T, imagePath, guestPath string, hostContent []byte) {
	t.Helper()
	hostFile := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(hostFile, hostContent, 0o600); err != nil {
		t.Fatalf("writing host fixture file: %v", err)
	}
	cmd := exec.Command("debugfs", "-w", "-R", "write "+hostFile+" "+guestPath, imagePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("debugfs write: %v (%s)", err, out)
	}
}

func debugfsMkdir(t *testing.T, imagePath, guestPath string) {
	t.Helper()
	cmd := exec.Command("debugfs", "-w", "-R", "mkdir "+guestPath, imagePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("debugfs mkdir: %v (%s)", err, out)
	}
}

func TestCountMutatedFiles_DetectsAddedRemovedAndChanged(t *testing.T) {
	requireE2fsprogs(t)
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.img")
	post := filepath.Join(dir, "post.img")

	makeExt4Image(t, pre, 8)
	debugfsWrite(t, pre, "/keep.txt", []byte("content-v1"))
	debugfsWrite(t, pre, "/removed.txt", []byte("content-v1"))

	makeExt4Image(t, post, 8)
	debugfsWrite(t, post, "/keep.txt", []byte("content-v1")) // unchanged
	debugfsWrite(t, post, "/added.txt", []byte("content-v2-longer"))
	debugfsMkdir(t, post, "/subdir")
	debugfsWrite(t, post, "/subdir/nested.txt", []byte("content-v2-longer"))

	mutated, err := countMutatedFiles(pre, post)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// removed.txt (removed) + added.txt (added) + subdir/nested.txt (added) = 3.
	// keep.txt is unchanged and must not count; /subdir itself is a
	// directory, not a regular file, and must not count either.
	if mutated != 3 {
		t.Fatalf("expected 3 mutated files, got %d", mutated)
	}
}

func TestCountMutatedFiles_IdenticalImagesHaveZeroMutation(t *testing.T) {
	requireE2fsprogs(t)
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.img")
	post := filepath.Join(dir, "post.img")

	makeExt4Image(t, pre, 8)
	debugfsWrite(t, pre, "/same.txt", []byte("unchanged"))

	makeExt4Image(t, post, 8)
	debugfsWrite(t, post, "/same.txt", []byte("unchanged"))

	mutated, err := countMutatedFiles(pre, post)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated != 0 {
		t.Fatalf("expected 0 mutated files for identical content, got %d", mutated)
	}
}

func TestCountMutatedFiles_DetectsContentSizeChange(t *testing.T) {
	requireE2fsprogs(t)
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.img")
	post := filepath.Join(dir, "post.img")

	makeExt4Image(t, pre, 8)
	debugfsWrite(t, pre, "/file.txt", []byte("short"))

	makeExt4Image(t, post, 8)
	debugfsWrite(t, post, "/file.txt", []byte("a much longer replacement body"))

	mutated, err := countMutatedFiles(pre, post)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated != 1 {
		t.Fatalf("expected 1 mutated file for a size change, got %d", mutated)
	}
}

func TestCountMutatedFiles_MissingImageErrors(t *testing.T) {
	requireE2fsprogs(t)
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.img")
	makeExt4Image(t, pre, 8)

	if _, err := countMutatedFiles(pre, filepath.Join(dir, "does-not-exist.img")); err == nil {
		t.Fatal("expected an error for a missing post-image")
	}
}

func TestDebugfsLsLine_ParsesRealOutputFormat(t *testing.T) {
	line := []byte("     12  100644 (1)      0      0      11  7-Oct-2026 12:54 keep.txt")
	m := debugfsLsLine.FindSubmatch(line)
	if m == nil {
		t.Fatal("expected the regex to match a real debugfs ls -l line")
	}
	if string(m[1]) != "12" {
		t.Errorf("expected inode 12, got %q", m[1])
	}
	if string(m[2]) != "1" {
		t.Errorf("expected filetype 1, got %q", m[2])
	}
	if string(m[3]) != "11" {
		t.Errorf("expected size 11, got %q", m[3])
	}
	if string(m[5]) != "keep.txt" {
		t.Errorf("expected name 'keep.txt', got %q", m[5])
	}
}
