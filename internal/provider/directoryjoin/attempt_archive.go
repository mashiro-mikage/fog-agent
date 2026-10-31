package directoryjoin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

// All marker writers cooperate on this persistent, kernel-locked file. The
// file is never unlinked: a process exit releases the lock without creating
// a second lock inode while another writer still holds the first one.
func withAttemptLock(dir string, fn func() error) error {
	f, err := os.OpenFile(filepath.Join(dir, "directory-rejoin.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = lockAttemptFile(f); err != nil {
		return err
	}
	defer unlockAttemptFile(f)
	return fn()
}

// ArchiveVerifiedAttempt retires only the exact terminal snapshot the caller
// inspected. The same-directory move preserves its original bytes. A crash
// leaves either the old active verified marker or the archive, never an
// absent latch for an operation whose native outcome is uncertain.
func ArchiveVerifiedAttempt(dir string, expected *Attempt) error {
	return withAttemptLock(dir, func() error {
		current, err := LoadAttempt(dir)
		if err != nil {
			return err
		}
		if expected == nil || current == nil || current.Phase != "verified" || !reflect.DeepEqual(current, expected) {
			return errors.New("directory verified marker changed; archive refused")
		}
		path := AttemptPath(dir)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		dest := filepath.Join(dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
		if _, err = os.Lstat(dest); !os.IsNotExist(err) {
			return errors.New("directory verified archive already exists or cannot be inspected")
		}
		if err = archiveAttemptFile(path, dest); err != nil {
			return err
		}
		return syncAttemptDir(dir)
	})
}

// ValidateReservedRetry permits only an identity-bound v2 reservation for which
// no local native dispatch or result has been recorded. Server authorization
// does not make an uncertain marker safe to discard.
func ValidateReservedRetry(a *Attempt, p RejoinPlan, hostID int, fingerprint string) error {
	if a == nil || a.Version != 2 || a.Plan.Version != 2 || a.Phase != "reserved" ||
		a.Plan.Phase != "ready" || a.NativeStatus != nil || a.RebootRequested ||
		a.Plan.HostID != hostID || a.Fingerprint != fingerprint || len(fingerprint) != 64 ||
		a.Plan.Validate(hostID) != nil || p.Version != 2 || p.Phase != "ready" ||
		p.Validate(hostID) != nil || !p.RetryAuthorized ||
		a.Plan.AttemptID == p.AttemptID || a.Plan.ConfigRevision == p.ConfigRevision {
		return errors.New("previous directory operation is not a safe unexecuted reservation")
	}
	return nil
}

// RemoveAttemptForRetry rechecks the caller's retry permission and exact marker
// snapshot under the same file lock used before recording may_have_run.
func RemoveAttemptForRetry(dir string, expected *Attempt, p RejoinPlan, hostID int, fingerprint string) error {
	return withAttemptLock(dir, func() error {
		current, err := LoadAttempt(dir)
		if err != nil {
			return err
		}
		if expected == nil || current == nil || !reflect.DeepEqual(current, expected) {
			return errors.New("directory retry marker changed; removal refused")
		}
		if err = ValidateReservedRetry(current, p, hostID, fingerprint); err != nil {
			return err
		}
		if err = os.Remove(AttemptPath(dir)); err != nil {
			return err
		}
		return syncAttemptDir(dir)
	})
}
