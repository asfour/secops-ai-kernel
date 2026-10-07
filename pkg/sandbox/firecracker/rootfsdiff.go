package firecracker

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

// This file computes a real FilesMutated count for an ext4 rootfs image by
// shelling out to debugfs (part of e2fsprogs) to list directory contents
// directly from the flat image file — no loopback mount, no CAP_SYS_ADMIN,
// no root required. See IMPROVEMENT_SPEC.md item #9: a loopback-mount
// approach needs privileges not available in every deployment environment,
// and a no-root ext4-reading Go library (github.com/diskfs/go-diskfs) failed
// to parse even a trivial synthetic image during evaluation. debugfs is a
// standard e2fsprogs tool and is already a build/runtime dependency of this
// project (see setup.sh).

// ext2FileType mirrors the (N) filetype column debugfs prints, which comes
// from the on-disk directory entry's filetype byte (EXT2_FT_* constants),
// not the inode's full mode bits.
const ext2FileTypeRegular = 1
const ext2FileTypeDir = 2

type rootfsEntry struct {
	inode    uint64
	filetype int
	size     uint64
	mtime    string // opaque comparison key; debugfs's own date+time string
}

var debugfsLsLine = regexp.MustCompile(
	`^\s*(\d+)\s+\d+\s+\((\d+)\)\s+\d+\s+\d+\s+(\d+)\s+(\S+\s+\S+)\s+(.+?)\s*$`,
)

// debugfsLs lists one directory's entries inside an ext4 image via
// `debugfs -R "ls -l <dirPath>" <imagePath>`, skipping "." and "..".
func debugfsLs(imagePath, dirPath string) ([]struct {
	name  string
	entry rootfsEntry
}, error) {
	cmd := exec.Command("debugfs", "-R", fmt.Sprintf("ls -l %s", dirPath), imagePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("debugfs ls %q %q: %w (stderr: %s)", imagePath, dirPath, err, stderr.String())
	}
	// debugfs exits 0 even when it fails to open the image or the path
	// doesn't exist — it just prints an error to stderr and "ls" reports
	// "Filesystem not open" on stdout. Surface that as a real error
	// instead of silently returning an empty manifest.
	if bytes.Contains(stderr.Bytes(), []byte("No such file or directory")) ||
		bytes.Contains(stdout.Bytes(), []byte("Filesystem not open")) {
		return nil, fmt.Errorf("debugfs could not open %q (stderr: %s)", imagePath, stderr.String())
	}

	var results []struct {
		name  string
		entry rootfsEntry
	}
	for _, line := range bytes.Split(stdout.Bytes(), []byte("\n")) {
		m := debugfsLsLine.FindSubmatch(line)
		if m == nil {
			continue // version banner / blank lines / anything unparseable
		}
		name := string(m[5])
		if name == "." || name == ".." {
			continue
		}
		inode, _ := strconv.ParseUint(string(m[1]), 10, 64)
		filetype, _ := strconv.Atoi(string(m[2]))
		size, _ := strconv.ParseUint(string(m[3]), 10, 64)
		results = append(results, struct {
			name  string
			entry rootfsEntry
		}{
			name: name,
			entry: rootfsEntry{
				inode:    inode,
				filetype: filetype,
				size:     size,
				mtime:    string(m[4]),
			},
		})
	}
	return results, nil
}

// rootfsManifest recursively walks imagePath starting at "/" and returns a
// map from full path to rootfsEntry, for both regular files and
// directories.
func rootfsManifest(imagePath string) (map[string]rootfsEntry, error) {
	manifest := make(map[string]rootfsEntry)
	var walk func(dirPath string) error
	walk = func(dirPath string) error {
		entries, err := debugfsLs(imagePath, dirPath)
		if err != nil {
			return err
		}
		for _, e := range entries {
			fullPath := dirPath
			if fullPath != "/" {
				fullPath += "/"
			}
			fullPath += e.name
			manifest[fullPath] = e.entry
			if e.entry.filetype == ext2FileTypeDir {
				if err := walk(fullPath); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("/"); err != nil {
		return nil, err
	}
	return manifest, nil
}

// countMutatedFiles diffs the regular-file entries of two ext4 images and
// returns how many paths were added, removed, or changed (differing inode
// or size). Directory entries are walked (to reach their contents) but not
// themselves counted, matching StateDiffMetrics.files_mutated's naming.
func countMutatedFiles(preImagePath, postImagePath string) (uint64, error) {
	pre, err := rootfsManifest(preImagePath)
	if err != nil {
		return 0, fmt.Errorf("reading pre-execution rootfs manifest: %w", err)
	}
	post, err := rootfsManifest(postImagePath)
	if err != nil {
		return 0, fmt.Errorf("reading post-execution rootfs manifest: %w", err)
	}

	var mutated uint64
	seen := make(map[string]bool, len(pre)+len(post))
	for path, preEntry := range pre {
		seen[path] = true
		if preEntry.filetype != ext2FileTypeRegular {
			continue
		}
		postEntry, ok := post[path]
		if !ok || postEntry.filetype != ext2FileTypeRegular {
			mutated++ // removed (or replaced by a non-regular entry)
			continue
		}
		if postEntry.inode != preEntry.inode || postEntry.size != preEntry.size {
			mutated++ // content changed
		}
	}
	for path, postEntry := range post {
		if seen[path] {
			continue
		}
		if postEntry.filetype == ext2FileTypeRegular {
			mutated++ // added
		}
	}
	return mutated, nil
}
