package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
	"github.com/FOGProject/fog-agent/internal/reboot"
)

func TestCaptureCloneBRotateArchivesAAndClaimsNewReadyOperationOnce(t *testing.T) {
	for _, tc := range []struct {
		name              string
		resetAndReEnrollA bool
	}{
		{name: "matching key usual clone"},
		{name: "verified A reset and re-enroll before clone B", resetAndReEnrollA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			oldFP, err := st.KeyFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 101 // Clone A's old enrollment.
			old := &directoryjoin.Attempt{Version: 2, Fingerprint: oldFP, Plan: directoryOperationPlan("rebind", "existing"), Phase: "verified"}
			old.Plan.HostID, old.Plan.ExpectedCurrent, old.Plan.ExpectedPending = 101, "A", "A"
			if err = directoryjoin.ReserveAttempt(st.Dir, old); err != nil {
				t.Fatal(err)
			}
			oldBytes, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(oldBytes)
			archive := filepath.Join(st.Dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
			assertOldArchive := func(stage string) {
				t.Helper()
				got, e := os.ReadFile(archive)
				if e != nil || !bytes.Equal(got, oldBytes) {
					t.Fatalf("%s: old A marker archive not byte preserving: equal=%t err=%v", stage, bytes.Equal(got, oldBytes), e)
				}
			}

			if tc.resetAndReEnrollA {
				// First reset the verified A identity with no clone source, then
				// model A's successful re-enrollment under its new key.
				if err = st.RotateIdentity(identity.Host{}); err != nil {
					t.Fatalf("same-A RotateIdentity: %v", err)
				}
				assertOldArchive("same-A reset")
				midFP, e := st.KeyFingerprint()
				if e != nil || midFP == oldFP {
					t.Fatalf("same-A reset did not create a fresh key: old=%q new=%q err=%v", oldFP, midFP, e)
				}
				st.Config.HostID = 111 // A's re-enrollment returns a new host binding.
				if err = st.SaveConfig(); err != nil {
					t.Fatalf("save re-enrolled A host: %v", err)
				}
				if err = st.RotateIdentity(identity.Host{}); err != nil {
					t.Fatalf("captureCloneBRotate(source A): %v", err)
				}
				newFP, e := st.KeyFingerprint()
				if e != nil || newFP == midFP {
					t.Fatalf("clone B did not create a fresh key: A=%q B=%q err=%v", midFP, newFP, e)
				}
			} else {
				if err = st.RotateIdentity(identity.Host{}); err != nil {
					t.Fatalf("captureCloneBRotate(source A): %v", err)
				}
				newFP, e := st.KeyFingerprint()
				if e != nil || newFP == oldFP {
					t.Fatalf("clone B retained clone A key: old=%q new=%q err=%v", oldFP, newFP, e)
				}
			}
			assertOldArchive("clone B capture")
			if _, e := os.Stat(directoryjoin.AttemptPath(st.Dir)); !os.IsNotExist(e) {
				t.Fatalf("old active marker remains: %v", e)
			}

			// Enrollment assigns B a distinct server host after local rotation.
			st.Config.HostID = 202
			plan := directoryOperationPlan("rebind", "existing")
			plan.HostID, plan.ExpectedCurrent, plan.ExpectedPending = 202, "A", "B"
			starts, claims, natives := 0, 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/agent/v1/directory/rejoin/start":
					starts++
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
						"domain": plan.Domain, "username": `CORP\\fixture`, "password": "fixture-secret", "reboot": false, "rejoin": plan,
					}})
				case "/agent/v1/result":
					claims++
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			oldObserve, oldRebind, oldSetName := observeRejoin, rebindDirectory, setRejoinName
			t.Cleanup(func() { observeRejoin, rebindDirectory, setRejoinName = oldObserve, oldRebind, oldSetName })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "B", Domain: plan.Domain, Role: "workstation"}, nil
			}
			setRejoinName = func(string) error { return nil }
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			if err = processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
				t.Fatalf("new B operation: %v", err)
			}
			marker, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || marker == nil || marker.Plan.HostID != 202 || marker.Phase != "awaiting_reboot" {
				t.Fatalf("new host marker absent: marker=%+v err=%v", marker, err)
			}
			if starts != 1 || claims != 1 || natives != 1 {
				t.Fatalf("operation counts starts=%d claims=%d native=%d, want one each", starts, claims, natives)
			}
		})
	}
}

func TestCoordinateSkipsStaleDirectoryRebootReason(t *testing.T) {
	for _, tc := range []struct {
		name            string
		phase           string
		archiveMarker   bool
		rebootRequested bool
	}{
		{name: "verified", phase: "verified"},
		{name: "archived marker absent", phase: "verified", archiveMarker: true},
		{name: "unknown", phase: "unknown"},
		{name: "may_have_run", phase: "may_have_run"},
		{name: "awaiting reboot already requested", phase: "awaiting_reboot", rebootRequested: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, plan := newDirectoryBoundaryState(t)
			fingerprint, err := st.KeyFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			attempt := &directoryjoin.Attempt{
				Version: 2, Fingerprint: fingerprint, Plan: plan,
				Phase: tc.phase, RebootRequested: tc.rebootRequested,
			}
			if err = directoryjoin.ReserveAttempt(st.Dir, attempt); err != nil {
				t.Fatal(err)
			}
			if tc.archiveMarker {
				if err = directoryjoin.ArchiveVerifiedAttempt(st.Dir, attempt); err != nil {
					t.Fatalf("archive verified marker: %v", err)
				}
			}
			st.Config.PendingReboot = []reboot.Reason{{Source: "directory-rejoin", Detail: "stale rejoin reason", Mode: reboot.ModeReboot}}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/agent/v1/result" {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			}))
			defer server.Close()

			oldUsers, oldRequest := rebootUsers, requestReboot
			t.Cleanup(func() { rebootUsers, requestReboot = oldUsers, oldRequest })
			usersCalls, rebootCalls := 0, 0
			rebootUsers = func() (int, error) { usersCalls++; return 0, nil }
			requestReboot = func(string, time.Duration, string) error {
				rebootCalls++
				return nil
			}
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			if err = coordinateForPlatform(context.Background(), st, client, &sayer{}, true); err != nil {
				t.Fatalf("coordinate stale directory reason: %v", err)
			}
			if rebootCalls != 0 || usersCalls != 1 {
				t.Fatalf("stale reason reached reboot path: requestReboot=%d rebootUsers=%d, want 0/1", rebootCalls, usersCalls)
			}
		})
	}
}

func TestCoordinateKeepsTaskRebootWithheldUntilDirectoryVerified(t *testing.T) {
	st, plan := newDirectoryBoundaryState(t)
	fingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	attempt := &directoryjoin.Attempt{Version: 2, Fingerprint: fingerprint, Plan: plan, Phase: "unknown"}
	if err = directoryjoin.ReserveAttempt(st.Dir, attempt); err != nil {
		t.Fatal(err)
	}
	taskReason := reboot.Reason{Source: reboot.SourceTask, Detail: "imaging task", TaskID: 731}
	st.Config.PendingReboot = []reboot.Reason{
		{Source: "directory-rejoin", Detail: "stale rejoin reason", Mode: reboot.ModeReboot},
		taskReason,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/result" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	oldUsers, oldRequest := rebootUsers, requestReboot
	t.Cleanup(func() { rebootUsers, requestReboot = oldUsers, oldRequest })
	usersCalls, rebootCalls := 0, 0
	rebootUsers = func() (int, error) { usersCalls++; return 0, nil }
	requestReboot = func(string, time.Duration, string) error { rebootCalls++; return nil }
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
	if err = coordinateForPlatform(context.Background(), st, client, &sayer{}, true); err != nil {
		t.Fatalf("coordinate unverified directory/task reasons: %v", err)
	}
	if rebootCalls != 0 || usersCalls != 1 {
		t.Fatalf("unverified directory marker released task reboot: requestReboot=%d rebootUsers=%d", rebootCalls, usersCalls)
	}
	if len(st.Config.PendingReboot) != 1 || st.Config.PendingReboot[0] != taskReason {
		t.Fatalf("task reboot reason was not preserved while directory verification is incomplete: %+v", st.Config.PendingReboot)
	}
}

func TestRejectedOrLostClaimRemainsUncertainAcrossReloadWithoutNativeReplay(t *testing.T) {
	for _, mode := range []string{"rejected", "response-lost"} {
		t.Run(mode, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 303
			plan := directoryOperationPlan("rebind", "existing")
			plan.HostID = 303
			plan.ExpectedPending = "B"
			starts, natives := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/agent/v1/directory/rejoin/start" {
					http.NotFound(w, r)
					return
				}
				if r.URL.Path == "/agent/v1/directory/rejoin/start" {
					starts++
				}
				if mode == "response-lost" {
					hj := w.(http.Hijacker)
					conn, _, e := hj.Hijack()
					if e == nil {
						_ = conn.Close()
					}
					return
				}
				http.Error(w, "claim refused", http.StatusConflict)
			}))
			defer server.Close()
			oldObserve, oldRebind := observeRejoin, rebindDirectory
			t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "B", Domain: plan.Domain, Role: "workstation"}, nil
			}
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			opErr := processRejoin(context.Background(), st, client, &plan, &sayer{})
			if opErr == nil {
				t.Fatal("failed claim returned success")
			}
			reloaded, err := enroll.Load(st.Dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := directoryjoin.LoadAttempt(reloaded.Dir)
			if err != nil || got == nil || got.Phase != "unknown" || got.Fingerprint == "" || got.Plan.HostID != 303 {
				t.Fatalf("uncertain claim marker not retained after reload: marker=%+v loadErr=%v operationErr=%v starts=%d natives=%d", got, err, opErr, starts, natives)
			}
			if err = processRejoin(context.Background(), reloaded, client, nil, &sayer{}); err == nil || !strings.Contains(err.Error(), "server confirmation") {
				t.Fatalf("restart replay guard error=%v", err)
			}
			if starts != 1 || natives != 0 {
				t.Fatalf("restart repeated mutation: starts=%d native=%d", starts, natives)
			}
		})
	}
}

func TestRejoinUsesBothKeyAndHostForVerifiedMarkerOwnership(t *testing.T) {
	for _, tc := range []struct {
		name          string
		markerHost    int
		markerFPMatch bool
		wantArchive   bool
	}{
		{name: "same key and host", markerHost: 606, markerFPMatch: true},
		{name: "same host different key", markerHost: 606, markerFPMatch: false, wantArchive: true},
		{name: "same key different host", markerHost: 607, markerFPMatch: true, wantArchive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			fp, err := st.KeyFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 606
			markerFP := fp
			if !tc.markerFPMatch {
				markerFP = strings.Repeat("f", 64)
			}
			p := directoryOperationPlan("rebind", "existing")
			p.HostID = tc.markerHost
			marker := &directoryjoin.Attempt{Version: 2, Fingerprint: markerFP, Plan: p, Phase: "verified"}
			if err = directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "verified marker must not claim", 500) }))
			defer server.Close()
			if err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, nil, &sayer{}); err != nil {
				t.Fatalf("processRejoin(nil): %v", err)
			}
			_, activeErr := os.Stat(directoryjoin.AttemptPath(st.Dir))
			if tc.wantArchive {
				digest := sha256.Sum256(before)
				archived, e := os.ReadFile(filepath.Join(st.Dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json"))
				if e != nil || !bytes.Equal(archived, before) || !os.IsNotExist(activeErr) {
					t.Fatalf("foreign marker disposition wrong: archiveEqual=%t archiveErr=%v activeErr=%v", bytes.Equal(archived, before), e, activeErr)
				}
			} else if activeErr != nil {
				t.Fatalf("matching key and HostID marker was archived: %v", activeErr)
			}
		})
	}
}

func TestRejoinArchivesForeignVerifiedMarkerWithoutIdentityRotation(t *testing.T) {
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	fp, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = 404
	foreign := &directoryjoin.Attempt{Version: 2, Fingerprint: strings.Repeat("f", 64), Plan: directoryOperationPlan("rebind", "existing"), Phase: "verified"}
	foreign.Plan.HostID = 404
	if err = directoryjoin.ReserveAttempt(st.Dir, foreign); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	if err != nil {
		t.Fatal(err)
	}
	if fp == foreign.Fingerprint {
		t.Fatal("fixture fingerprint unexpectedly matched")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nil plan must not claim", 500) }))
	defer server.Close()
	if err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, nil, &sayer{}); err != nil {
		t.Fatalf("processRejoin(nil): %v", err)
	}
	digest := sha256.Sum256(before)
	archive := filepath.Join(st.Dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
	if got, e := os.ReadFile(archive); e != nil || !bytes.Equal(got, before) {
		t.Fatalf("foreign marker not archived byte-for-byte: equal=%t err=%v", bytes.Equal(got, before), e)
	}
	if _, e := os.Stat(directoryjoin.AttemptPath(st.Dir)); !os.IsNotExist(e) {
		t.Fatalf("foreign active marker remains: %v", e)
	}
}

func TestRejoinPreservesUncertainAndIdentityHostMismatchMarkers(t *testing.T) {
	for _, phase := range []string{"unknown", "may_have_run", "awaiting_reboot", "failed", "reserved"} {
		t.Run(phase, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = st.EnsureKey(identity.Host{}); err != nil {
				t.Fatal(err)
			}
			fp, err := st.KeyFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			st.Config.HostID = 505
			p := directoryOperationPlan("rebind", "existing")
			p.HostID = 505
			a := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: p, Phase: phase}
			if err = directoryjoin.ReserveAttempt(st.Dir, a); err != nil {
				t.Fatal(err)
			}
			path := directoryjoin.AttemptPath(st.Dir)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			starts, natives := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/agent/v1/directory/rejoin/start" {
					starts++
				}
				http.Error(w, "must not claim", 500)
			}))
			defer server.Close()
			oldObserve, oldRebind := observeRejoin, rebindDirectory
			t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) { return directoryjoin.RejoinObservation{}, nil }
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			plan := directoryOperationPlan("rebind", "existing")
			plan.HostID = 505
			_ = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &plan, &sayer{})
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || got == nil || got.Phase != phase || got.Fingerprint != fp || got.Plan.HostID != 505 {
				t.Fatalf("marker changed: %+v err=%v", got, err)
			}
			if !bytes.Equal(before, after) || starts != 0 || natives != 0 {
				t.Fatalf("uncertain marker altered/dispatched: same=%t starts=%d native=%d", bytes.Equal(before, after), starts, natives)
			}
		})
	}
}
