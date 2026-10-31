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

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

func p1RetryState(t *testing.T, hostID int) (*enroll.State, string) {
	t.Helper()
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = hostID
	fp, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return st, fp
}

func p1RetryReadyPlan(hostID int) directoryjoin.RejoinPlan {
	p := directoryOperationPlan("rebind", "existing")
	p.HostID = hostID
	p.AttemptID = strings.Repeat("e", 32)
	p.ConfigRevision = strings.Repeat("f", 32)
	p.ExpectedPending = p.Name
	p.RetryAuthorized = true
	return p
}

func p1RetryTestServer(t *testing.T, plan directoryjoin.RejoinPlan, starts, results *int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			(*starts)++
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
				"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": false, "rejoin": plan,
			}})
		case "/agent/v1/result":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode result request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			item, _ := body["item"].(map[string]any)
			if item["task_id"] != float64(plan.TaskID) || item["attempt_id"] != plan.AttemptID || item["config_revision"] != plan.ConfigRevision || item["status"] != "awaiting_reboot" || item["native_status"] != float64(0) || item["exit_code"] != float64(0) {
				t.Errorf("result claim does not match successful plan: %#v", item)
			}
			(*results)++
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestProcessRejoinRetryAuthorizedCannotRetireUncertainMarkers(t *testing.T) {
	for _, phase := range []string{"unknown", "failed", "may_have_run", "awaiting_reboot"} {
		t.Run(phase, func(t *testing.T) {
			st, fp := p1RetryState(t, 71)
			oldPlan := directoryOperationPlan("rebind", "existing")
			oldPlan.AttemptID = strings.Repeat("c", 32)
			oldPlan.ConfigRevision = strings.Repeat("d", 32)
			marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: oldPlan, Phase: phase}
			if phase == "awaiting_reboot" {
				marker.RebootRequested = true
				marker.BeforeBoot = directoryjoin.BootObservation{Marker: "before"}
			}
			if phase == "failed" {
				code := uint32(5)
				marker.NativeStatus = &code
			}
			if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
				t.Fatal(err)
			}
			markerPath := directoryjoin.AttemptPath(st.Dir)
			before, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			newPlan := p1RetryReadyPlan(st.Config.HostID)
			starts, results, natives, observations := 0, 0, 0, 0
			server := p1RetryTestServer(t, newPlan, &starts, &results)
			defer server.Close()
			oldObserve, oldRebind := observeRejoin, rebindDirectory
			t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				observations++
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "A", Domain: newPlan.Domain, Role: "workstation"}, nil
			}
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			if err = processRejoin(context.Background(), st, client, &newPlan, &sayer{}); err == nil {
				t.Fatal("RetryAuthorized ready plan retired an uncertain marker")
			}
			after, readErr := os.ReadFile(markerPath)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("uncertain marker changed: sameBytes=%t readErr=%v", bytes.Equal(before, after), readErr)
			}
			if starts != 0 || results != 0 || natives != 0 || observations != 0 {
				t.Fatalf("uncertain marker reached operation path: starts=%d results=%d native=%d observe=%d", starts, results, natives, observations)
			}
		})
	}
}

func TestProcessRejoinRetryAuthorizedRejectsMismatchedReservedMarker(t *testing.T) {
	for _, mismatch := range []string{"host", "fingerprint"} {
		t.Run(mismatch, func(t *testing.T) {
			st, fp := p1RetryState(t, 71)
			oldPlan := directoryOperationPlan("rebind", "existing")
			oldPlan.AttemptID = strings.Repeat("c", 32)
			oldPlan.ConfigRevision = strings.Repeat("d", 32)
			markerFP := fp
			if mismatch == "host" {
				oldPlan.HostID = 72
			} else {
				markerFP = strings.Repeat("9", 64)
			}
			marker := &directoryjoin.Attempt{Version: 2, Fingerprint: markerFP, Plan: oldPlan, Phase: "reserved"}
			if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
				t.Fatal(err)
			}
			markerPath := directoryjoin.AttemptPath(st.Dir)
			before, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			newPlan := p1RetryReadyPlan(st.Config.HostID)
			starts, results, natives, observations := 0, 0, 0, 0
			server := p1RetryTestServer(t, newPlan, &starts, &results)
			defer server.Close()
			oldObserve, oldRebind := observeRejoin, rebindDirectory
			t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				observations++
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "A", Domain: newPlan.Domain, Role: "workstation"}, nil
			}
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}
			if err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &newPlan, &sayer{}); err == nil {
				t.Fatalf("RetryAuthorized plan retired reserved marker with %s mismatch", mismatch)
			}
			after, readErr := os.ReadFile(markerPath)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("mismatched marker changed: sameBytes=%t readErr=%v", bytes.Equal(before, after), readErr)
			}
			if starts != 0 || results != 0 || natives != 0 || observations != 0 {
				t.Fatalf("mismatched marker reached operation path: starts=%d results=%d native=%d observe=%d", starts, results, natives, observations)
			}
		})
	}
}

func TestProcessRejoinRetryAuthorizedRetiresOnlyReservedMarkerThenUsesNormalClaim(t *testing.T) {
	st, fp := p1RetryState(t, 71)
	oldPlan := directoryOperationPlan("rebind", "existing")
	oldPlan.AttemptID = strings.Repeat("c", 32)
	oldPlan.ConfigRevision = strings.Repeat("d", 32)
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: oldPlan, Phase: "reserved"}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}
	newPlan := p1RetryReadyPlan(st.Config.HostID)
	starts, results, natives, observations := 0, 0, 0, 0
	server := p1RetryTestServer(t, newPlan, &starts, &results)
	defer server.Close()
	oldObserve, oldRebind := observeRejoin, rebindDirectory
	t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observations++
		return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: newPlan.ExpectedPending, Domain: newPlan.Domain, Role: "workstation"}, nil
	}
	rebindDirectory = func(_ context.Context, _ directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		if got.AttemptID != newPlan.AttemptID || got.ConfigRevision != newPlan.ConfigRevision || got.Operation != "rebind" || got.Mode != "existing" {
			t.Errorf("native call did not use authorized new plan: %+v", got)
		}
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &newPlan, &sayer{}); err != nil {
		t.Fatalf("authorized reserved retry: %v", err)
	}
	got, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || got == nil || got.Plan.AttemptID != newPlan.AttemptID || got.Plan.ConfigRevision != newPlan.ConfigRevision || got.Phase != "awaiting_reboot" || got.NativeStatus == nil || *got.NativeStatus != 0 {
		t.Fatalf("new normal attempt not recorded: marker=%+v err=%v", got, err)
	}
	if starts != 1 || results != 1 || natives != 1 || observations != 2 {
		t.Fatalf("authorized retry did not take normal claim/result path exactly once: starts=%d results=%d native=%d observe=%d", starts, results, natives, observations)
	}
}

func TestRemoveAttemptForRetryRefusesChangedMarkerSnapshot(t *testing.T) {
	st, fp := p1RetryState(t, 71)
	oldPlan := directoryOperationPlan("rebind", "existing")
	oldPlan.AttemptID = strings.Repeat("c", 32)
	oldPlan.ConfigRevision = strings.Repeat("d", 32)
	expected := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: oldPlan, Phase: "reserved"}
	if err := directoryjoin.ReserveAttempt(st.Dir, expected); err != nil {
		t.Fatal(err)
	}
	changed := *expected
	changed.Phase = "may_have_run"
	if err := directoryjoin.SaveAttempt(st.Dir, &changed); err != nil {
		t.Fatalf("prepare changed snapshot: %v", err)
	}
	before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	if err != nil {
		t.Fatal(err)
	}
	newPlan := p1RetryReadyPlan(st.Config.HostID)
	if err = directoryjoin.RemoveAttemptForRetry(st.Dir, expected, newPlan, st.Config.HostID, fp); err == nil {
		t.Fatal("retry removal accepted a marker that changed after its snapshot was read")
	}
	after, readErr := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	got, loadErr := directoryjoin.LoadAttempt(st.Dir)
	if readErr != nil || loadErr != nil || got == nil || got.Phase != "may_have_run" || !bytes.Equal(before, after) {
		t.Fatalf("changed marker was removed or rewritten: rawSame=%t marker=%+v readErr=%v loadErr=%v", bytes.Equal(before, after), got, readErr, loadErr)
	}
}

func TestProcessRejoinSameAttemptVerifiedResponsePreservesLocalAwaitingMarker(t *testing.T) {
	st, fp := p1RetryState(t, 71)
	plan := directoryOperationPlan("rebind", "existing")
	plan.Phase = "ready"
	boot := directoryjoin.BootObservation{Marker: "boot-before", Started: "2026-10-30T00:00:00Z"}
	code := uint32(0)
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: plan, Phase: "awaiting_reboot", BeforeBoot: boot, NativeStatus: &code, RebootRequested: true}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	if err != nil {
		t.Fatal(err)
	}
	plan.Phase = "verified"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "same-attempt verified response must not start or report", http.StatusInternalServerError)
	}))
	defer server.Close()
	oldObserve, oldRebind := observeRejoin, rebindDirectory
	t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
	observations, natives := 0, 0
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observations++
		return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: plan.ExpectedPending, Domain: plan.Domain, Role: "workstation", Boot: boot}, nil
	}
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &plan, &sayer{}); err != nil {
		t.Fatalf("same-attempt lost-ACK recovery: %v", err)
	}
	after, readErr := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	got, loadErr := directoryjoin.LoadAttempt(st.Dir)
	if readErr != nil || loadErr != nil || got == nil || got.Phase != "awaiting_reboot" || !bytes.Equal(before, after) {
		t.Fatalf("server verified response retired local awaiting marker: rawSame=%t marker=%+v readErr=%v loadErr=%v", bytes.Equal(before, after), got, readErr, loadErr)
	}
	if observations != 1 || natives != 0 {
		t.Fatalf("same-attempt recovery performed unexpected work: observations=%d native=%d", observations, natives)
	}
}

func TestProcessRejoinSameAttemptVerifiedResponseCompletesLostAckAfterHealthyNewBoot(t *testing.T) {
	st, fp := p1RetryState(t, 71)
	localPlan := directoryOperationPlan("rebind", "existing")
	bootBefore := directoryjoin.BootObservation{Marker: "boot-before", Started: "2026-10-30T00:00:00Z"}
	nativeStatus := uint32(0)
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: localPlan, Phase: "awaiting_reboot", BeforeBoot: bootBefore, NativeStatus: &nativeStatus, RebootRequested: true}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}
	serverPlan := localPlan
	serverPlan.Phase = "verified"
	serverPlan.RetryAuthorized = true
	starts, results := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			starts++
			http.Error(w, "same-attempt recovery must not start a new claim", http.StatusInternalServerError)
		case "/agent/v1/result":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode verified result request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			item, _ := body["item"].(map[string]any)
			if item["task_id"] != float64(localPlan.TaskID) || item["attempt_id"] != localPlan.AttemptID || item["config_revision"] != localPlan.ConfigRevision || item["status"] != "verified" || item["native_status"] != float64(0) || item["exit_code"] != float64(0) || item["boot_changed"] != true {
				t.Errorf("verified result does not match recovered old attempt: %#v", item)
			}
			results++
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	oldObserve, oldRebind := observeRejoin, rebindDirectory
	t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
	observations, natives := 0, 0
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observations++
		return directoryjoin.RejoinObservation{
			CurrentName: "B", PendingName: "B", Domain: localPlan.Domain, Netbios: "CORP",
			Role: "workstation", SecureChannel: "true",
			Boot: directoryjoin.BootObservation{Marker: "boot-after", Started: "2026-10-31T00:00:00Z"},
		}, nil
	}
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &serverPlan, &sayer{}); err != nil {
		t.Fatalf("same-attempt lost-ACK completion: %v", err)
	}
	got, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || got == nil || got.Phase != "verified" || got.Plan.AttemptID != localPlan.AttemptID || got.Plan.ConfigRevision != localPlan.ConfigRevision {
		t.Fatalf("old attempt did not converge to verified: marker=%+v err=%v", got, err)
	}
	if starts != 0 || results != 1 || natives != 0 || observations != 1 {
		t.Fatalf("same-attempt recovery used unexpected path: starts=%d results=%d native=%d observe=%d", starts, results, natives, observations)
	}
}

func TestProcessRejoinForeignVerifiedMarkerStillArchivesAndContinues(t *testing.T) {
	st, fp := p1RetryState(t, 71)
	oldPlan := directoryOperationPlan("rebind", "existing")
	oldPlan.AttemptID = strings.Repeat("c", 32)
	oldPlan.ConfigRevision = strings.Repeat("d", 32)
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: strings.Repeat("9", 64), Plan: oldPlan, Phase: "verified"}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
	if err != nil {
		t.Fatal(err)
	}
	newPlan := p1RetryReadyPlan(st.Config.HostID)
	newPlan.RetryAuthorized = false
	starts, results, natives, observations := 0, 0, 0, 0
	server := p1RetryTestServer(t, newPlan, &starts, &results)
	defer server.Close()
	oldObserve, oldRebind := observeRejoin, rebindDirectory
	t.Cleanup(func() { observeRejoin, rebindDirectory = oldObserve, oldRebind })
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observations++
		return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: newPlan.ExpectedPending, Domain: newPlan.Domain, Role: "workstation"}, nil
	}
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err = processRejoin(context.Background(), st, &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}, &newPlan, &sayer{}); err != nil {
		t.Fatalf("new operation after verified archive: %v", err)
	}
	digest := sha256.Sum256(before)
	archive := filepath.Join(st.Dir, "directory-rejoin-verified-"+hex.EncodeToString(digest[:])+".json")
	archived, archiveErr := os.ReadFile(archive)
	active, activeErr := os.Stat(directoryjoin.AttemptPath(st.Dir))
	got, loadErr := directoryjoin.LoadAttempt(st.Dir)
	if archiveErr != nil || !bytes.Equal(archived, before) || activeErr != nil || active == nil || loadErr != nil || got == nil || got.Plan.AttemptID != newPlan.AttemptID {
		t.Fatalf("verified archive/new operation disposition wrong: archiveEqual=%t archiveErr=%v activeErr=%v marker=%+v loadErr=%v", bytes.Equal(archived, before), archiveErr, activeErr, got, loadErr)
	}
	if starts != 1 || results != 1 || natives != 1 || observations != 2 || fp == marker.Fingerprint {
		t.Fatalf("verified archive did not continue through fresh normal claim/result: starts=%d results=%d native=%d observe=%d", starts, results, natives, observations)
	}
}
