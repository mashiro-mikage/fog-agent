package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
	"github.com/FOGProject/fog-agent/internal/reboot"
)

func TestDirectoryClaimFailureNeverChangesPendingNameOrRunsNative(t *testing.T) {
	for _, tc := range []struct {
		name         string
		loseResponse bool
		reason       string
	}{
		{name: "claim refused", reason: "directory_claim_refused"},
		{name: "DB fence timeout before claim", reason: "directory_fence_timeout"},
		{name: "claim response lost", loseResponse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, plan := newDirectoryBoundaryState(t)
			starts, results, sets, natives := 0, 0, 0, 0
			pendingName := "A"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/agent/v1/directory/rejoin/start":
					starts++
					if tc.loseResponse {
						h, ok := w.(http.Hijacker)
						if !ok {
							t.Error("test server does not support connection hijacking")
							return
						}
						conn, _, err := h.Hijack()
						if err != nil {
							t.Errorf("hijack start response: %v", err)
							return
						}
						_ = conn.Close()
						return
					}
					w.WriteHeader(http.StatusConflict)
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "reason": tc.reason})
				case "/agent/v1/result":
					results++
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			oldObserve, oldSet, oldRebind := observeRejoin, setRejoinName, rebindDirectory
			t.Cleanup(func() { observeRejoin, setRejoinName, rebindDirectory = oldObserve, oldSet, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: "A", Domain: plan.Domain, Role: "workstation"}, nil
			}
			setRejoinName = func(name string) error { sets++; pendingName = name; return nil }
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}

			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil {
				t.Fatal("unconfirmed claim was accepted")
			}
			marker, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || marker == nil || marker.Phase != "unknown" {
				t.Fatalf("failed claim did not leave unknown marker: marker=%+v err=%v", marker, err)
			}
			before, err := json.Marshal(marker)
			if err != nil {
				t.Fatal(err)
			}
			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil {
				t.Fatal("unknown claim outcome was replayed")
			}
			afterMarker, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || afterMarker == nil || afterMarker.Phase != "unknown" {
				t.Fatalf("unknown marker lost after retry attempt: marker=%+v err=%v", afterMarker, err)
			}
			after, err := json.Marshal(afterMarker)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("retry attempt changed the unknown marker")
			}
			if starts != 1 || sets != 0 || natives != 0 || results != 1 {
				t.Fatalf("claim/retry calls: start=%d set-name=%d native=%d result=%d", starts, sets, natives, results)
			}
			if pendingName != "A" {
				t.Fatalf("pending name changed on failed claim: %q", pendingName)
			}
		})
	}
}

func TestDirectoryNameMutationFailureStaysUnknownAndDoesNotReplayNative(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setErr     bool
		observeErr bool
	}{
		{name: "set-name error", setErr: true},
		{name: "post-set observation error", observeErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, plan := newDirectoryBoundaryState(t)
			starts, results, sets, observes, natives := 0, 0, 0, 0, 0
			pendingName := "A"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/agent/v1/directory/rejoin/start":
					starts++
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
						"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": false, "rejoin": plan,
					}})
				case "/agent/v1/result":
					results++
					_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			oldObserve, oldSet, oldRebind := observeRejoin, setRejoinName, rebindDirectory
			t.Cleanup(func() { observeRejoin, setRejoinName, rebindDirectory = oldObserve, oldSet, oldRebind })
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
				observes++
				if tc.observeErr && observes > 1 {
					return directoryjoin.RejoinObservation{}, errors.New("post-set observation failed")
				}
				return directoryjoin.RejoinObservation{CurrentName: "A", PendingName: pendingName, Domain: plan.Domain, Role: "workstation"}, nil
			}
			setRejoinName = func(name string) error {
				sets++
				marker, err := directoryjoin.LoadAttempt(st.Dir)
				if err != nil || marker == nil || marker.Phase != "may_have_run" {
					t.Errorf("SetRejoinName called without may_have_run marker: marker=%+v err=%v", marker, err)
				}
				if starts != 1 {
					t.Errorf("SetRejoinName called before server claim: starts=%d", starts)
				}
				if name != plan.Name {
					t.Errorf("SetRejoinName(%q), want %q", name, plan.Name)
				}
				pendingName = name
				if !tc.setErr {
					// The outcome may be uncertain even when the setter returns an error.
					return nil
				}
				return errors.New("set-name outcome uncertain")
			}
			rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
				natives++
				return 0, nil
			}

			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil || !strings.Contains(err.Error(), "requires review") {
				t.Fatalf("processRejoin error = %v, want mutation uncertainty STOP", err)
			}
			marker, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || marker == nil || marker.Phase != "unknown" {
				t.Fatalf("name mutation failure did not persist unknown marker: marker=%+v err=%v", marker, err)
			}
			before, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
			if err != nil {
				t.Fatal(err)
			}
			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil {
				t.Fatal("unknown name mutation outcome was replayed")
			}
			after, err := os.ReadFile(directoryjoin.AttemptPath(st.Dir))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("retry attempt changed the unknown marker")
			}
			wantObserves := 2
			if tc.setErr {
				wantObserves = 1
			}
			if starts != 1 || sets != 1 || natives != 0 || observes != wantObserves || results != 2 {
				t.Fatalf("mutation/retry calls: start=%d set-name=%d observe=%d native=%d result=%d, want observe=%d", starts, sets, observes, natives, results, wantObserves)
			}
		})
	}
}

func TestRefusedDirectoryRebootClearsLatchForNextCoordinate(t *testing.T) {
	st, plan := newDirectoryBoundaryState(t)
	fingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	attempt := &directoryjoin.Attempt{Version: 2, Fingerprint: fingerprint, Plan: plan, Phase: "awaiting_reboot", RebootRequested: true}
	if err := directoryjoin.ReserveAttempt(st.Dir, attempt); err != nil {
		t.Fatal(err)
	}
	if err := refusedDirectoryReboot(st, attempt, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || loaded == nil || loaded.Phase != "awaiting_reboot" || loaded.RebootRequested {
		t.Fatalf("known refusal did not clear persisted latch: marker=%+v err=%v", loaded, err)
	}
}

func TestCoordinateRetriesKnownRefusedDirectoryReboot(t *testing.T) {
	st, plan := newDirectoryBoundaryState(t)
	fingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	attempt := &directoryjoin.Attempt{Version: 2, Fingerprint: fingerprint, Plan: plan, Phase: "awaiting_reboot"}
	if err := directoryjoin.ReserveAttempt(st.Dir, attempt); err != nil {
		t.Fatal(err)
	}
	st.Config.PendingReboot = []reboot.Reason{{Source: "directory-rejoin", Detail: "test rejoin", Mode: reboot.ModeReboot}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/v1/result" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
	oldUsers, oldRequest := rebootUsers, requestReboot
	t.Cleanup(func() { rebootUsers, requestReboot = oldUsers, oldRequest })
	requests := 0
	rebootUsersCalls := 0
	rebootUsers = func() (int, error) { rebootUsersCalls++; return 0, nil }
	requestReboot = func(mode string, delay time.Duration, message string) error {
		requests++
		if mode != reboot.ModeReboot {
			t.Errorf("request mode = %q, want reboot", mode)
		}
		if requests == 1 {
			return errors.New("known reboot refusal")
		}
		return nil
	}
	if err := coordinateForPlatform(context.Background(), st, client, &sayer{}, true); err == nil {
		t.Fatal("first known reboot refusal was not returned")
	}
	marker, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker == nil || marker.RebootRequested {
		t.Fatalf("refused request latch not reset: marker=%+v err=%v", marker, err)
	}
	if len(st.Config.PendingReboot) != 1 || st.Config.PendingReboot[0].Source != "directory-rejoin" {
		t.Fatalf("refused reboot reason not restored: %+v", st.Config.PendingReboot)
	}
	if err := coordinateForPlatform(context.Background(), st, client, &sayer{}, true); err != nil {
		t.Fatalf("second coordinate attempt: %v", err)
	}
	marker, err = directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker == nil || !marker.RebootRequested {
		t.Fatalf("accepted retry latch not persisted: marker=%+v err=%v", marker, err)
	}
	if requests != 2 || rebootUsersCalls != 2 {
		t.Fatalf("coordinator calls: request=%d logged-in lookup=%d, want 2/2", requests, rebootUsersCalls)
	}
	if len(st.Config.PendingReboot) != 0 {
		t.Fatalf("accepted reboot reason remained pending: %+v", st.Config.PendingReboot)
	}
}

func newDirectoryBoundaryState(t *testing.T) (*enroll.State, directoryjoin.RejoinPlan) {
	t.Helper()
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	plan := directoryOperationPlan("rebind", "create")
	st.Config.HostID = plan.HostID
	return st, plan
}
