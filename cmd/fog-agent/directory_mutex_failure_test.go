package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

func TestDirectoryMutexCleanupErrorStaysUnknownAndNeverFallsBack(t *testing.T) {
	st, _ := newDirectoryBoundaryState(t)
	plan := directoryOperationPlan("rebind", "existing")
	st.Config.HostID = plan.HostID

	const releaseFailure = "synthetic directory mutex release failed"
	startCalls, resultCalls := 0, 0
	nativeCalls, renameCalls, joinCalls, nameCalls := 0, 0, 0, 0
	pendingName := plan.ExpectedPending

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			startCalls++
			if r.Method != http.MethodPost {
				t.Errorf("start method = %s, want POST", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"directory": map[string]any{
					"domain": plan.Domain, "username": `CORP\fixture`,
					"password": "test-secret", "reboot": false, "rejoin": plan,
				},
			})
		case "/agent/v1/result":
			resultCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode result: %v", err)
				return
			}
			item, _ := body["item"].(map[string]any)
			if item["status"] != "unknown" {
				t.Errorf("cleanup error result status = %#v, want unknown", item["status"])
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}

	oldObserve, oldSetName := observeRejoin, setRejoinName
	oldRebind, oldRename, oldJoin := rebindDirectory, renameDirectory, joinDirectory
	t.Cleanup(func() {
		observeRejoin, setRejoinName = oldObserve, oldSetName
		rebindDirectory, renameDirectory, joinDirectory = oldRebind, oldRename, oldJoin
	})
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		return directoryjoin.RejoinObservation{
			CurrentName: "A", PendingName: pendingName, Domain: plan.Domain,
			Role: "workstation",
		}, nil
	}
	setRejoinName = func(name string) error {
		nameCalls++
		pendingName = name
		return nil
	}
	rebindDirectory = func(_ context.Context, _ directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
		nativeCalls++
		if got.Operation != "rebind" || got.Mode != "existing" {
			t.Errorf("native plan changed to fallback: operation=%q mode=%q", got.Operation, got.Mode)
		}
		// The native action completed successfully; only mutex cleanup failed.
		return 0, errors.New(releaseFailure)
	}
	renameDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		renameCalls++
		return 0, nil
	}
	joinDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		joinCalls++
		return 0, nil
	}

	var firstMarker []byte
	for attempt := 1; attempt <= 3; attempt++ {
		err := processRejoin(context.Background(), st, client, &plan, &sayer{})
		if err == nil || !strings.Contains(err.Error(), "outcome unknown") {
			t.Fatalf("processRejoin attempt %d error = %v, want unknown outcome", attempt, err)
		}
		if plan.Operation != "rebind" || plan.Mode != "existing" {
			t.Fatalf("attempt %d changed the input plan to fallback: operation=%q mode=%q", attempt, plan.Operation, plan.Mode)
		}

		marker, loadErr := directoryjoin.LoadAttempt(st.Dir)
		if loadErr != nil || marker == nil || marker.Phase != "unknown" {
			t.Fatalf("attempt %d marker = %+v, err = %v; want unknown", attempt, marker, loadErr)
		}
		if marker.Plan.Operation != "rebind" || marker.Plan.Mode != "existing" {
			t.Fatalf("attempt %d marker plan fell back: operation=%q mode=%q", attempt, marker.Plan.Operation, marker.Plan.Mode)
		}
		if marker.NativeStatus != nil {
			t.Fatalf("attempt %d recorded native status despite cleanup error: %v", attempt, *marker.NativeStatus)
		}
		markerBytes, marshalErr := json.Marshal(marker)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if attempt == 1 {
			firstMarker = markerBytes
		} else if !bytes.Equal(markerBytes, firstMarker) {
			t.Fatalf("attempt %d changed the unresolved marker: before=%s after=%s", attempt, firstMarker, markerBytes)
		}
		if nativeCalls != 1 {
			t.Fatalf("native calls after attempt %d = %d, want exactly one", attempt, nativeCalls)
		}
		if renameCalls != 0 || joinCalls != 0 {
			t.Fatalf("fallback calls after attempt %d: rename=%d join=%d", attempt, renameCalls, joinCalls)
		}
	}

	if startCalls != 1 || resultCalls != 3 || nativeCalls != 1 || nameCalls != 1 {
		t.Fatalf("calls: start=%d result=%d native=%d set-name=%d; want 1/3/1/1", startCalls, resultCalls, nativeCalls, nameCalls)
	}
}
