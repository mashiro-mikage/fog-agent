//go:build windows

package directoryjoin

import (
	"golang.org/x/sys/windows"
	"os"
)

func lockAttemptFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func unlockAttemptFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}
func archiveAttemptFile(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// No REPLACE_EXISTING: an existing history file is never overwritten.
	return windows.MoveFileEx(f, t, windows.MOVEFILE_WRITE_THROUGH)
}

// Windows moves above are write-through; marker contents are flushed by
// writeAttemptFile. Directory handles do not support portable File.Sync.
func syncAttemptDir(string) error { return nil }
