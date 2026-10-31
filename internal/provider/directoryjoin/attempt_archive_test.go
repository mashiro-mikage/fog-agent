package directoryjoin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func verifiedArchiveAttempt() *Attempt {
	a := validMJ1Attempt()
	a.Phase = "verified"
	return a
}

func putAttempt(t *testing.T, dir string, a *Attempt) []byte {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestArchiveVerifiedAttemptMovesExactSnapshotToDigestName(t *testing.T) {
	dir := t.TempDir()
	a := verifiedArchiveAttempt()
	b := putAttempt(t, dir, a)
	got, err := LoadAttempt(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := ArchiveVerifiedAttempt(dir, got); err != nil {
		t.Fatalf("archive verified attempt: %v", err)
	}
	if active, err := os.Lstat(AttemptPath(dir)); !os.IsNotExist(err) || active != nil {
		t.Fatalf("active marker remains after archive: info=%v err=%v", active, err)
	}
	digest := sha256.Sum256(b)
	archive := filepath.Join(dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
	archived, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if string(archived) != string(b) {
		t.Fatal("archive bytes differ from the exact active marker snapshot")
	}
}

func TestArchiveVerifiedAttemptRejectsNonVerifiedAndChangedSnapshotsPreservingBytes(t *testing.T) {
	for _, phase := range []string{"reserved", "may_have_run", "awaiting_reboot", "failed", "unknown"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			a := verifiedArchiveAttempt()
			a.Phase = phase
			before := putAttempt(t, dir, a)
			if err := ArchiveVerifiedAttempt(dir, a); err == nil {
				t.Fatal("archive accepted a non-verified marker")
			}
			after, err := os.ReadFile(AttemptPath(dir))
			if err != nil || string(after) != string(before) {
				t.Fatalf("marker changed on rejected archive: equal=%t err=%v", string(after) == string(before), err)
			}
		})
	}

	t.Run("stale expected snapshot", func(t *testing.T) {
		dir := t.TempDir()
		current := verifiedArchiveAttempt()
		putAttempt(t, dir, current)
		stale := verifiedArchiveAttempt()
		stale.RebootRequested = true
		before, err := os.ReadFile(AttemptPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := ArchiveVerifiedAttempt(dir, stale); err == nil {
			t.Fatal("archive accepted a stale expected snapshot")
		}
		after, err := os.ReadFile(AttemptPath(dir))
		if err != nil || string(after) != string(before) {
			t.Fatalf("marker changed on stale snapshot: equal=%t err=%v", string(after) == string(before), err)
		}
	})
}

func TestArchiveVerifiedAttemptCollisionFailsClosedWithoutOverwritingHistory(t *testing.T) {
	dir := t.TempDir()
	a := verifiedArchiveAttempt()
	active := putAttempt(t, dir, a)
	digest := sha256.Sum256(active)
	archive := filepath.Join(dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
	history := []byte("pre-existing history")
	if err := os.WriteFile(archive, history, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveVerifiedAttempt(dir, a); err == nil {
		t.Fatal("archive collision unexpectedly succeeded")
	}
	gotHistory, err := os.ReadFile(archive)
	if err != nil || string(gotHistory) != string(history) {
		t.Fatalf("existing archive changed: bytes=%q err=%v", gotHistory, err)
	}
	gotActive, err := os.ReadFile(AttemptPath(dir))
	if err != nil || string(gotActive) != string(active) {
		t.Fatalf("active marker changed after collision: equal=%t err=%v", string(gotActive) == string(active), err)
	}
}

func TestSaveAttemptAfterArchiveRejectsStaleWriter(t *testing.T) {
	dir := t.TempDir()
	a := verifiedArchiveAttempt()
	putAttempt(t, dir, a)
	staleWriter := *a
	if err := ArchiveVerifiedAttempt(dir, a); err != nil {
		t.Fatal(err)
	}
	staleWriter.Phase = "unknown"
	if err := SaveAttempt(dir, &staleWriter); err == nil {
		t.Fatal("stale SaveAttempt succeeded after its marker was archived")
	}
	if active, err := os.Lstat(AttemptPath(dir)); !os.IsNotExist(err) || active != nil {
		t.Fatalf("stale writer recreated active marker: info=%v err=%v", active, err)
	}
}

func TestSetAttemptRebootRequestedUsesFullSnapshotCAS(t *testing.T) {
	dir := t.TempDir()

	old := verifiedArchiveAttempt()
	oldBytes := putAttempt(t, dir, old)
	if err := ArchiveVerifiedAttempt(dir, old); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(oldBytes)
	historyPath := filepath.Join(dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")

	current := validMJ1Attempt()
	current.Plan.AttemptID = "dddddddddddddddddddddddddddddddd"
	current.Phase = "awaiting_reboot"
	if err := ReserveAttempt(dir, current); err != nil {
		t.Fatal(err)
	}
	staleFalse := *current
	if err := SetAttemptRebootRequested(dir, &staleFalse, true); err != nil {
		t.Fatalf("set reboot requested: %v", err)
	}

	if err := SetAttemptRebootRequested(dir, &staleFalse, false); err == nil {
		t.Fatal("stale false snapshot cleared a newer reboot request")
	}
	if err := SaveAttempt(dir, &staleFalse); err == nil {
		t.Fatal("SaveAttempt changed RebootRequested outside the dedicated CAS API")
	}

	fresh, err := LoadAttempt(dir)
	if err != nil || fresh == nil || !fresh.RebootRequested {
		t.Fatalf("stale writer changed reboot latch: marker=%+v err=%v", fresh, err)
	}
	if err := SetAttemptRebootRequested(dir, fresh, false); err != nil {
		t.Fatalf("clear reboot latch after known refusal: %v", err)
	}
	after, err := LoadAttempt(dir)
	if err != nil || after == nil || after.RebootRequested || after.Plan.AttemptID != current.Plan.AttemptID ||
		after.Fingerprint != current.Fingerprint || after.Phase != current.Phase {
		t.Fatalf("known-refusal CAS did not preserve the new binding: marker=%+v err=%v", after, err)
	}
	historyAfter, err := os.ReadFile(historyPath)
	if err != nil || string(historyAfter) != string(oldBytes) {
		t.Fatalf("history changed during reboot-latch CAS: equal=%t err=%v", string(historyAfter) == string(oldBytes), err)
	}
}

func TestSaveAttemptRejectsPhaseRegressionAfterVerification(t *testing.T) {
	dir := t.TempDir()
	awaiting := verifiedArchiveAttempt()
	awaiting.Phase = "awaiting_reboot"
	if err := ReserveAttempt(dir, awaiting); err != nil {
		t.Fatal(err)
	}
	verified := *awaiting
	verified.Phase = "verified"
	if err := SaveAttempt(dir, &verified); err != nil {
		t.Fatalf("save verified phase: %v", err)
	}
	stale := *awaiting
	if err := SaveAttempt(dir, &stale); err == nil {
		t.Fatal("stale awaiting_reboot writer regressed a verified marker")
	}
	got, err := LoadAttempt(dir)
	if err != nil || got == nil || got.Phase != "verified" {
		t.Fatalf("verified phase was not preserved: marker=%+v err=%v", got, err)
	}
}

func TestArchiveThenReserveRejectsOldSaveWithoutClobberingNewMarker(t *testing.T) {
	dir := t.TempDir()
	old := verifiedArchiveAttempt()
	putAttempt(t, dir, old)
	staleWriter := *old
	if err := ArchiveVerifiedAttempt(dir, old); err != nil {
		t.Fatal(err)
	}
	newAttempt := validMJ1Attempt()
	newAttempt.Plan.AttemptID = "dddddddddddddddddddddddddddddddd"
	if err := ReserveAttempt(dir, newAttempt); err != nil {
		t.Fatal(err)
	}
	if err := SaveAttempt(dir, &staleWriter); err == nil {
		t.Fatal("old writer overwrote a newly reserved attempt")
	}
	got, err := LoadAttempt(dir)
	if err != nil || got == nil || got.Plan.AttemptID != newAttempt.Plan.AttemptID || got.Phase != newAttempt.Phase {
		t.Fatalf("new marker was clobbered by stale writer: marker=%+v err=%v", got, err)
	}
}

func TestConcurrentReserveAndArchiveRemainCompatible(t *testing.T) {
	for i := 0; i < 20; i++ {
		dir := t.TempDir()
		old := verifiedArchiveAttempt()
		putAttempt(t, dir, old)
		reserved := validMJ1Attempt()
		reserved.Plan.AttemptID = string("0123456789abcdef"[i%16]) + reserved.Plan.AttemptID[1:]

		start := make(chan struct{})
		var wg sync.WaitGroup
		var archiveErr, reserveErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			archiveErr = ArchiveVerifiedAttempt(dir, old)
		}()
		go func() {
			defer wg.Done()
			<-start
			reserveErr = ReserveAttempt(dir, reserved)
		}()
		close(start)
		wg.Wait()
		archived, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		archiveCount := 0
		for _, entry := range archived {
			if strings.HasPrefix(entry.Name(), "directory-rejoin-verified-") {
				archiveCount++
			}
		}
		if archiveCount > 1 {
			t.Fatalf("iteration %d created %d archives", i, archiveCount)
		}
		var archiveBytes []byte
		if archiveCount == 1 {
			for _, entry := range archived {
				if strings.HasPrefix(entry.Name(), "directory-rejoin-verified-") {
					archiveBytes, err = os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		active, err := LoadAttempt(dir)
		if err != nil {
			t.Fatal(err)
		}
		oldBytes, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		if archiveCount == 1 && string(archiveBytes) != string(oldBytes) {
			t.Fatalf("iteration %d archive does not contain the old marker snapshot", i)
		}
		if reserveErr == nil && (active == nil || active.Plan.AttemptID != reserved.Plan.AttemptID || active.Phase != reserved.Phase) {
			t.Fatalf("iteration %d successful reserve missing or clobbered: %+v", i, active)
		}
		if active != nil && active.Plan.AttemptID != old.Plan.AttemptID && active.Plan.AttemptID != reserved.Plan.AttemptID {
			t.Fatalf("iteration %d unexpected marker clobbered active state: %+v", i, active)
		}
		if archiveErr == nil && active != nil && active.Plan.AttemptID == old.Plan.AttemptID {
			t.Fatalf("iteration %d successful archive left the old marker active: %+v", i, active)
		}
		if archiveErr != nil && reserveErr != nil && (archiveCount != 0 || active == nil || active.Plan.AttemptID != old.Plan.AttemptID || active.Phase != old.Phase) {
			t.Fatalf("iteration %d both operations failed without preserving old active marker: archiveCount=%d active=%+v archiveErr=%v reserveErr=%v", i, archiveCount, active, archiveErr, reserveErr)
		}
		if reserveErr == nil && archiveCount != 1 {
			t.Fatalf("iteration %d reserve succeeded without preserving archived history", i)
		}
		if archiveErr == nil && archiveCount != 1 {
			t.Fatalf("iteration %d archive succeeded without history", i)
		}
	}
}

func TestAttemptLockReleasedWhenProcessExits(t *testing.T) {
	if dir := os.Getenv("FOG_ATTEMPT_LOCK_EXIT_DIR"); dir != "" {
		_ = withAttemptLock(dir, func() error { os.Exit(0); return nil })
		os.Exit(2)
	}

	dir := t.TempDir()
	putAttempt(t, dir, verifiedArchiveAttempt())
	cmd := exec.Command(os.Args[0], "-test.run=^TestAttemptLockReleasedWhenProcessExits$")
	cmd.Env = append(os.Environ(), "FOG_ATTEMPT_LOCK_EXIT_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock holder subprocess: %v: %s", err, out)
	}
	if err := ArchiveVerifiedAttempt(dir, verifiedArchiveAttempt()); err != nil {
		t.Fatalf("archive after lock holder process exit: %v", err)
	}
}
