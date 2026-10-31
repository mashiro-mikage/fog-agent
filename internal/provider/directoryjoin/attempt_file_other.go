//go:build !unix && !windows

package directoryjoin

import (
	"errors"
	"os"
)

func lockAttemptFile(*os.File) error {
	return errors.New("directory marker locking unsupported on this platform")
}
func unlockAttemptFile(*os.File) {}
func archiveAttemptFile(string, string) error {
	return errors.New("directory marker archive unsupported on this platform")
}
func syncAttemptDir(string) error {
	return errors.New("directory marker sync unsupported on this platform")
}
