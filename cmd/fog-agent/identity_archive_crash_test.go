package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

// Exit without running defers at each durable boundary, then reload the
// actual files in the parent. No OS directory operation is executed.
func TestMarkerArchiveCrashBoundaries(t *testing.T) {
	if dir := os.Getenv("FOG_ARCHIVE_CRASH_DIR"); dir != "" {
		st, err := enroll.Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		old, err := directoryjoin.LoadAttempt(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = directoryjoin.ArchiveVerifiedAttempt(dir, old); err != nil {
			t.Fatal(err)
		}
		stage := os.Getenv("FOG_ARCHIVE_CRASH_STAGE")
		if stage != "archived" {
			fp, _ := st.KeyFingerprint()
			p := directoryOperationPlan("rebind", "existing")
			p.HostID, p.ExpectedPending = 202, "B"
			a := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: p, Phase: "reserved"}
			if err = directoryjoin.ReserveAttempt(dir, a); err != nil {
				t.Fatal(err)
			}
			if stage != "reserved" {
				a.Phase = "may_have_run"
				if err = directoryjoin.SaveAttempt(dir, a); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "partial-temp" {
				if err = os.WriteFile(directoryjoin.AttemptPath(dir)+".tmp", []byte(`{"phase":`), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		os.Exit(0)
	}
	for _, stage := range []string{"archived", "reserved", "may_have_run", "partial-temp"} {
		t.Run(stage, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 202
			if err = st.SaveConfig(); err != nil {
				t.Fatal(err)
			}
			oldPlan := directoryOperationPlan("rebind", "existing")
			oldPlan.HostID, oldPlan.AttemptID = 101, strings.Repeat("c", 32)
			old := &directoryjoin.Attempt{Version: 2, Fingerprint: strings.Repeat("f", 64), Plan: oldPlan, Phase: "verified"}
			if err = directoryjoin.ReserveAttempt(st.Dir, old); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestMarkerArchiveCrashBoundaries$")
			cmd.Env = append(os.Environ(), "FOG_ARCHIVE_CRASH_DIR="+st.Dir, "FOG_ARCHIVE_CRASH_STAGE="+stage)
			if output, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("crash helper: %v %s", e, output)
			}
			st, err = enroll.Load(st.Dir)
			if err != nil {
				t.Fatal(err)
			}
			histories, _ := filepath.Glob(filepath.Join(st.Dir, "directory-rejoin-verified-*.json"))
			if len(histories) != 1 {
				t.Fatalf("history count: %d", len(histories))
			}
			plan := directoryOperationPlan("rebind", "existing")
			plan.HostID, plan.ExpectedPending = 202, "B"
			claims, natives := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/agent/v1/directory/rejoin/start" {
					claims++
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{"domain": plan.Domain, "username": "fixture", "password": "fixture", "rejoin": plan}})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
				}
			}))
			defer server.Close()
			previousObserve, previousNative := observeRejoin, rebindDirectory
			defer func() { observeRejoin, rebindDirectory = previousObserve, previousNative }()
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "B", Domain: plan.Domain, Role: "workstation"}, nil
			}
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &plan, &sayer{})
			if stage == "archived" {
				if err != nil || claims != 1 || natives != 1 {
					t.Fatalf("fresh operation: %v claims=%d native=%d", err, claims, natives)
				}
			} else if err == nil || claims != 0 || natives != 0 {
				t.Fatalf("uncertain operation replayed: %v claims=%d native=%d", err, claims, natives)
			}
		})
	}
}
