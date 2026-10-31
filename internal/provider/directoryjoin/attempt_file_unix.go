//go:build unix

package directoryjoin

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockAttemptFile(f *os.File) error         { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func unlockAttemptFile(f *os.File)             { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func archiveAttemptFile(from, to string) error { return os.Rename(from, to) }
func syncAttemptDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
