package main

import (
	"context"
	"testing"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

func TestTargetOperationConflictingNameStopsBeforeStart(t *testing.T) {
	oldObserve, oldSet := observeRejoin, setRejoinName
	t.Cleanup(func() { observeRejoin, setRejoinName = oldObserve, oldSet })
	for _, names := range [][2]string{{"A", "C"}, {"C", "B"}, {"A", ""}} {
		t.Run(names[0]+"-"+names[1], func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			p := directoryOperationPlan("rebind", "create")
			st.Config.HostID = p.HostID
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				return directoryjoin.RejoinObservation{CurrentName: names[0], PendingName: names[1], Domain: p.Domain, Role: "workstation"}, nil
			}
			setRejoinName = func(string) error { t.Fatal("conflicting name overwritten"); return nil }
			if err = processRejoin(context.Background(), st, nil, &p, &sayer{}); err == nil {
				t.Fatal("conflict accepted")
			}
			if marker, err := directoryjoin.LoadAttempt(st.Dir); err != nil || marker != nil {
				t.Fatalf("unexpected attempt: %v %v", marker, err)
			}
		})
	}
}
