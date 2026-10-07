package firecracker

import (
	"io"
	"os"
)

// diffFiles streams two files in lockstep and returns the number of
// byte positions at which they differ, treating a shorter file's missing
// tail as zero bytes. It is a coarse but real measurement — unlike a
// placeholder hash, it actually observes the two snapshot files on disk
// (see IMPROVEMENT_SPEC.md item #6) — and avoids loading either
// file fully into memory, since guest memory snapshots can be large.
func diffFiles(pathA, pathB string) (uint64, error) {
	fA, err := os.Open(pathA)
	if err != nil {
		return 0, err
	}
	defer fA.Close()

	fB, err := os.Open(pathB)
	if err != nil {
		return 0, err
	}
	defer fB.Close()

	const bufSize = 64 * 1024
	bufA := make([]byte, bufSize)
	bufB := make([]byte, bufSize)
	var diff uint64

	for {
		nA, errA := fA.Read(bufA)
		nB, errB := fB.Read(bufB)

		n := nA
		if nB > n {
			n = nB
		}
		for i := 0; i < n; i++ {
			var a, b byte
			if i < nA {
				a = bufA[i]
			}
			if i < nB {
				b = bufB[i]
			}
			if a != b {
				diff++
			}
		}

		aDone := errA == io.EOF || (errA == nil && nA == 0)
		bDone := errB == io.EOF || (errB == nil && nB == 0)
		if aDone && bDone {
			break
		}
		if errA != nil && errA != io.EOF {
			return diff, errA
		}
		if errB != nil && errB != io.EOF {
			return diff, errB
		}
	}

	return diff, nil
}
