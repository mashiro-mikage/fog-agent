package directoryjoin

import (
	"crypto/sha256"
	"os"
	"strings"
	"sync"
	"testing"
)

func reservedRetryFixture() (*Attempt, RejoinPlan, int, string) {
	oldPlan := validV2Plan("rebind", "existing")
	oldPlan.Phase = "ready"

	a := validMJ1Attempt()
	a.Version = 2
	a.Plan = oldPlan
	a.Phase = "reserved"
	a.NativeStatus = nil
	a.RebootRequested = false

	newPlan := oldPlan
	newPlan.AttemptID = strings.Repeat("d", 32)
	newPlan.ConfigRevision = strings.Repeat("e", 32)
	newPlan.Phase = "ready"
	newPlan.RetryAuthorized = true

	return a, newPlan, oldPlan.HostID, a.Fingerprint
}

func markerHash(t *testing.T, dir string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(AttemptPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func TestValidateReservedRetryAcceptsOnlyBoundReadyV2Retry(t *testing.T) {
	a, next, hostID, fp := reservedRetryFixture()
	if err := ValidateReservedRetry(a, next, hostID, fp); err != nil {
		t.Fatalf("valid reserved retry rejected: %v", err)
	}
}

func TestValidateReservedRetryRejectsInvalidBindingsAndPlans(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Attempt, *RejoinPlan, *int, *string)
	}{
		{name: "wrong current host", mutate: func(_ *Attempt, _ *RejoinPlan, hostID *int, _ *string) { *hostID++ }},
		{name: "wrong fingerprint", mutate: func(_ *Attempt, _ *RejoinPlan, _ *int, fp *string) { *fp = strings.Repeat("9", 64) }},
		{name: "old plan wrong host", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { a.Plan.HostID++ }},
		{name: "old plan not ready", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { a.Plan.Phase = "planned" }},
		{name: "old plan wrong version", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { a.Plan.Version = 1 }},
		{name: "new plan wrong host", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.HostID++ }},
		{name: "new plan not ready", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.Phase = "planned" }},
		{name: "new plan wrong version", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.Version = 1 }},
		{name: "new plan retry not authorized", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.RetryAuthorized = false }},
		{name: "same attempt", mutate: func(a *Attempt, p *RejoinPlan, _ *int, _ *string) { p.AttemptID = a.Plan.AttemptID }},
		{name: "same config revision", mutate: func(a *Attempt, p *RejoinPlan, _ *int, _ *string) { p.ConfigRevision = a.Plan.ConfigRevision }},
		{name: "attempt version mismatch", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { a.Version = 1 }},
		{name: "native status present", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { status := uint32(0); a.NativeStatus = &status }},
		{name: "reboot already requested", mutate: func(a *Attempt, _ *RejoinPlan, _ *int, _ *string) { a.RebootRequested = true }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, next, hostID, fp := reservedRetryFixture()
			tc.mutate(a, &next, &hostID, &fp)
			if err := ValidateReservedRetry(a, next, hostID, fp); err == nil {
				t.Fatal("invalid retry binding or plan was accepted")
			}
		})
	}
}

func TestRemoveAttemptForRetryRejectsProtectedPhasesAndLegacyMarkerUnchanged(t *testing.T) {
	for _, phase := range []string{"may_have_run", "unknown", "failed", "awaiting_reboot", "verified"} {
		t.Run("v2-"+phase, func(t *testing.T) {
			dir := t.TempDir()
			a, next, hostID, fp := reservedRetryFixture()
			a.Phase = phase
			putAttempt(t, dir, a)
			before := markerHash(t, dir)

			if err := RemoveAttemptForRetry(dir, a, next, hostID, fp); err == nil {
				t.Fatal("protected v2 marker was removed for retry")
			}
			if after := markerHash(t, dir); after != before {
				t.Fatal("protected marker bytes changed after rejected retry")
			}
		})
	}

	t.Run("legacy reserved", func(t *testing.T) {
		dir := t.TempDir()
		legacy := validMJ1Attempt()
		putAttempt(t, dir, legacy)
		before := markerHash(t, dir)
		_, next, hostID, fp := reservedRetryFixture()

		if err := RemoveAttemptForRetry(dir, legacy, next, hostID, fp); err == nil {
			t.Fatal("legacy reserved marker was removed for v2 retry")
		}
		if after := markerHash(t, dir); after != before {
			t.Fatal("legacy marker bytes changed after rejected retry")
		}
	})
}

func TestRemoveAttemptForRetryRejectsInvalidRetryWithoutChangingMarker(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Attempt, *RejoinPlan, *int, *string)
	}{
		{name: "wrong host", mutate: func(_ *Attempt, _ *RejoinPlan, hostID *int, _ *string) { *hostID++ }},
		{name: "wrong fingerprint", mutate: func(_ *Attempt, _ *RejoinPlan, _ *int, fp *string) { *fp = strings.Repeat("9", 64) }},
		{name: "invalid new plan", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.Phase = "planned" }},
		{name: "same attempt", mutate: func(a *Attempt, p *RejoinPlan, _ *int, _ *string) { p.AttemptID = a.Plan.AttemptID }},
		{name: "same revision", mutate: func(a *Attempt, p *RejoinPlan, _ *int, _ *string) { p.ConfigRevision = a.Plan.ConfigRevision }},
		{name: "retry not authorized", mutate: func(_ *Attempt, p *RejoinPlan, _ *int, _ *string) { p.RetryAuthorized = false }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			a, next, hostID, fp := reservedRetryFixture()
			if err := ReserveAttempt(dir, a); err != nil {
				t.Fatalf("reserve fixture: %v", err)
			}
			tc.mutate(a, &next, &hostID, &fp)
			before := markerHash(t, dir)

			if err := RemoveAttemptForRetry(dir, a, next, hostID, fp); err == nil {
				t.Fatal("invalid retry was accepted")
			}
			if after := markerHash(t, dir); after != before {
				t.Fatal("marker bytes changed after rejected retry")
			}
		})
	}
}

func TestRemoveAttemptForRetryDeletesValidReservedV2Marker(t *testing.T) {
	dir := t.TempDir()
	a, next, hostID, fp := reservedRetryFixture()
	if err := ReserveAttempt(dir, a); err != nil {
		t.Fatalf("reserve fixture: %v", err)
	}
	current, err := LoadAttempt(dir)
	if err != nil || current == nil {
		t.Fatalf("load reserved fixture: marker=%+v err=%v", current, err)
	}
	if err := RemoveAttemptForRetry(dir, current, next, hostID, fp); err != nil {
		t.Fatalf("remove valid reserved marker: %v", err)
	}
	if current, err = LoadAttempt(dir); err != nil || current != nil {
		t.Fatalf("valid retry did not remove reserved marker: marker=%+v err=%v", current, err)
	}
}

func TestMayHaveRunSaveWinnerPreventsRetryRemoval(t *testing.T) {
	dir := t.TempDir()
	a, next, hostID, fp := reservedRetryFixture()
	if err := ReserveAttempt(dir, a); err != nil {
		t.Fatalf("reserve fixture: %v", err)
	}
	expected, err := LoadAttempt(dir)
	if err != nil || expected == nil {
		t.Fatalf("load reserved fixture: marker=%+v err=%v", expected, err)
	}

	mayHaveRun := *expected
	mayHaveRun.Phase = "may_have_run"
	if err := SaveAttempt(dir, &mayHaveRun); err != nil {
		t.Fatalf("save may_have_run winner: %v", err)
	}
	if err := RemoveAttemptForRetry(dir, expected, next, hostID, fp); err == nil {
		t.Fatal("retry removed marker after may_have_run won")
	}
	current, err := LoadAttempt(dir)
	if err != nil || current == nil || current.Phase != "may_have_run" {
		t.Fatalf("may_have_run winner was not preserved: marker=%+v err=%v", current, err)
	}
}

func TestRetryRemovalWinnerMakesOldMayHaveRunSaveFail(t *testing.T) {
	dir := t.TempDir()
	a, next, hostID, fp := reservedRetryFixture()
	if err := ReserveAttempt(dir, a); err != nil {
		t.Fatalf("reserve fixture: %v", err)
	}
	expected, err := LoadAttempt(dir)
	if err != nil || expected == nil {
		t.Fatalf("load reserved fixture: marker=%+v err=%v", expected, err)
	}
	oldWriter := *expected
	oldWriter.Phase = "may_have_run"

	if err := RemoveAttemptForRetry(dir, expected, next, hostID, fp); err != nil {
		t.Fatalf("remove reserved marker winner: %v", err)
	}
	if err := SaveAttempt(dir, &oldWriter); err == nil {
		t.Fatal("stale may_have_run save recreated a removed marker")
	}
	if current, err := LoadAttempt(dir); err != nil || current != nil {
		t.Fatalf("stale save recreated marker after retry won: marker=%+v err=%v", current, err)
	}
}

func TestRetryRemovalThenReserveRejectsOldSaveWithoutChangingNewMarker(t *testing.T) {
	dir := t.TempDir()
	old, next, hostID, fp := reservedRetryFixture()
	if err := ReserveAttempt(dir, old); err != nil {
		t.Fatalf("reserve old fixture: %v", err)
	}
	expected, err := LoadAttempt(dir)
	if err != nil || expected == nil {
		t.Fatalf("load old reserved fixture: marker=%+v err=%v", expected, err)
	}
	oldWriter := *expected
	oldWriter.Phase = "may_have_run"

	if err := RemoveAttemptForRetry(dir, expected, next, hostID, fp); err != nil {
		t.Fatalf("remove old reserved marker: %v", err)
	}
	newAttempt := &Attempt{
		Version:     2,
		Fingerprint: fp,
		Plan:        next,
		Phase:       "reserved",
	}
	if err := ReserveAttempt(dir, newAttempt); err != nil {
		t.Fatalf("reserve authorized new attempt: %v", err)
	}
	before := markerHash(t, dir)

	if err := SaveAttempt(dir, &oldWriter); err == nil {
		t.Fatal("stale old may_have_run writer replaced the newly reserved attempt")
	}
	if after := markerHash(t, dir); after != before {
		t.Fatal("new marker bytes changed after stale old save was rejected")
	}
	current, err := LoadAttempt(dir)
	if err != nil || current == nil || current.Plan.AttemptID != next.AttemptID || current.Phase != "reserved" {
		t.Fatalf("new reservation was not preserved: marker=%+v err=%v", current, err)
	}
}

func TestRetryRemovalRacesMayHaveRunSaveWithoutLosingEitherWinner(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run(strings.Repeat("x", i+1), func(t *testing.T) {
			dir := t.TempDir()
			a, next, hostID, fp := reservedRetryFixture()
			if err := ReserveAttempt(dir, a); err != nil {
				t.Fatalf("reserve fixture: %v", err)
			}
			expected, err := LoadAttempt(dir)
			if err != nil || expected == nil {
				t.Fatalf("load reserved fixture: marker=%+v err=%v", expected, err)
			}
			mayHaveRun := *expected
			mayHaveRun.Phase = "may_have_run"

			start := make(chan struct{})
			ready := make(chan struct{}, 2)
			var wg sync.WaitGroup
			var removeErr, saveErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				ready <- struct{}{}
				<-start
				removeErr = RemoveAttemptForRetry(dir, expected, next, hostID, fp)
			}()
			go func() {
				defer wg.Done()
				ready <- struct{}{}
				<-start
				saveErr = SaveAttempt(dir, &mayHaveRun)
			}()
			<-ready
			<-ready
			close(start)
			wg.Wait()

			current, loadErr := LoadAttempt(dir)
			if loadErr != nil {
				t.Fatalf("load race result: %v", loadErr)
			}
			switch {
			case removeErr == nil && saveErr != nil:
				if current != nil {
					t.Fatalf("retry won but marker remains: %+v", current)
				}
			case removeErr != nil && saveErr == nil:
				if current == nil || current.Phase != "may_have_run" {
					t.Fatalf("may_have_run save won but marker is not protected: %+v", current)
				}
			default:
				t.Fatalf("race did not have exactly one winner: removeErr=%v saveErr=%v marker=%+v", removeErr, saveErr, current)
			}
		})
	}
}
