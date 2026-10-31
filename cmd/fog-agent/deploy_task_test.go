package main

import (
	"context"
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

func TestLocalDirectoryAttemptSummaryIsDerivedAndOmitsCloneFields(t *testing.T) {
	for _, tc := range []struct {
		name          string
		marker        string
		wantPhase     string
		wantAttemptID string
		wantHostID    int
		wantFP        bool
	}{
		{name: "none", wantPhase: "none"},
		{name: "unknown", marker: "unknown", wantPhase: "unknown", wantAttemptID: strings.Repeat("a", 32), wantHostID: 71, wantFP: true},
		{name: "unreadable", marker: "unreadable", wantPhase: "unreadable"},
		{name: "terminal verified", marker: "verified", wantPhase: "verified", wantAttemptID: strings.Repeat("a", 32), wantHostID: 71, wantFP: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := enroll.Load(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			wantFingerprint := ""
			if tc.marker == "unknown" || tc.marker == "verified" {
				if _, err := st.EnsureKey(machine("machine-A")); err != nil {
					t.Fatal(err)
				}
				st.Config.HostID = 71
				fingerprint, err := st.KeyFingerprint()
				if err != nil {
					t.Fatal(err)
				}
				wantFingerprint = fingerprint
				plan := directoryOperationPlan("rebind", "existing")
				plan.AttemptID = tc.wantAttemptID
				if err := directoryjoin.ReserveAttempt(st.Dir, &directoryjoin.Attempt{
					Version: 2, Fingerprint: fingerprint, Plan: plan,
					Phase: map[string]string{"unknown": "unknown", "verified": "awaiting_reboot"}[tc.marker],
				}); err != nil {
					t.Fatal(err)
				}
				if tc.marker == "verified" {
					attempt, err := directoryjoin.LoadAttempt(st.Dir)
					if err != nil || attempt == nil {
						t.Fatalf("load reserved marker: marker=%+v err=%v", attempt, err)
					}
					attempt.Phase = "verified"
					if err := directoryjoin.SaveAttempt(st.Dir, attempt); err != nil {
						t.Fatalf("save verified marker: %v", err)
					}
				}
				st.Config.HostID = plan.HostID
			} else if tc.marker == "unreadable" {
				if err := os.WriteFile(filepath.Join(st.Dir, "directory-rejoin-attempt.json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			summary := localDirectoryAttempt(st.Dir)
			if summary == nil || summary.Phase != tc.wantPhase {
				t.Fatalf("directory attempt summary = %+v, want phase %q", summary, tc.wantPhase)
			}
			if summary.AttemptID != tc.wantAttemptID || summary.HostID != tc.wantHostID {
				t.Fatalf("directory attempt identity = %+v", summary)
			}
			if tc.wantFP != (summary.Fingerprint != "") {
				t.Fatalf("directory attempt fingerprint presence = %t, want %t", summary.Fingerprint != "", tc.wantFP)
			}
			if summary.Fingerprint != wantFingerprint {
				t.Fatalf("directory attempt fingerprint = %q, want %q", summary.Fingerprint, wantFingerprint)
			}
			request := enroll.PollRequest{DirectoryAttempt: summary}
			wire, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(wire, &fields); err != nil {
				t.Fatal(err)
			}
			attemptJSON, ok := fields["directory_attempt"]
			if !ok {
				t.Fatalf("directory_attempt absent from poll wire: %s", wire)
			}
			var attemptFields map[string]json.RawMessage
			if err := json.Unmarshal(attemptJSON, &attemptFields); err != nil {
				t.Fatal(err)
			}
			if tc.marker == "unreadable" && (len(attemptFields) != 1 || string(attemptFields["phase"]) != `"unreadable"`) {
				t.Fatalf("unreadable marker leaked details: %s", attemptJSON)
			}
			if strings.Contains(string(wire), "clone_status") || strings.Contains(string(wire), "clone_origin") {
				t.Fatalf("removed clone classification appeared on poll wire: %s", wire)
			}
		})
	}
}

func TestDeployTaskJoinFromWorkgroupVerifiesAfterOneNativeCall(t *testing.T) {
	plan := directoryjoin.RejoinPlan{
		TaskID: 909, Version: 2, Operation: "join",
		AttemptID: strings.Repeat("a", 32), HostID: 71,
		ConfigRevision: strings.Repeat("b", 32), Phase: "ready",
		Name: "B", Domain: "corp.example", Mode: "join", DC: "dc.corp.example",
		ExpectedCurrent: "B", ExpectedPending: "B",
	}
	if err := plan.Validate(plan.HostID); err != nil {
		t.Fatalf("invalid task join fixture: %v", err)
	}
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = plan.HostID

	phase := "ready"
	var starts, reports, joins int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			starts++
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode start request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request["task_id"] != float64(plan.TaskID) || request["operation"] != "join" {
				t.Errorf("task operation binding missing: %#v", request)
			}
			if phase != "ready" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "blocked"})
				return
			}
			phase = "started"
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
				"domain": plan.Domain, "netbios": "CORP", "username": `CORP\\joiner`,
				"password": "test-secret", "reboot": true, "rejoin": plan,
			}})
		case "/agent/v1/result":
			reports++
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode result request: %v", err)
			}
			item, _ := request["item"].(map[string]any)
			if item["task_id"] != float64(plan.TaskID) {
				t.Errorf("result task binding missing: %#v", item)
			}
			if item["status"] == "verified" && item["netbios"] != "CORP" {
				t.Errorf("verified Netbios was not reported: %#v", item)
			}
			switch item["status"] {
			case "awaiting_reboot", "verified":
				phase, _ = item["status"].(string)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}

	observation := directoryjoin.RejoinObservation{
		CurrentName: "B", PendingName: "B", Domain: "", Netbios: "", Role: "workstation",
		SecureChannel: "unknown", Boot: directoryjoin.BootObservation{Marker: "boot-a", Started: "2026-10-28T00:00:00Z"},
	}
	oldObserve, oldJoin := observeRejoin, joinDirectory
	t.Cleanup(func() { observeRejoin, joinDirectory = oldObserve, oldJoin })
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) { return observation, nil }
	joinDirectory = func(_ context.Context, policy directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
		joins++
		if got.Operation != "join" || got.TaskID != plan.TaskID || !policy.Reboot {
			t.Errorf("wrong Workgroup Join dispatch: plan=%+v reboot=%t", got, policy.Reboot)
		}
		return 0, nil
	}

	if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
		t.Fatalf("initial task join: %v", err)
	}
	marker, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker == nil || marker.Phase != "awaiting_reboot" {
		t.Fatalf("task join did not persist reboot wait: marker=%+v err=%v", marker, err)
	}
	if len(st.Config.PendingReboot) != 1 || st.Config.PendingReboot[0].Source != "directory-rejoin" {
		t.Fatalf("task join did not queue exactly one directory reboot: %+v", st.Config.PendingReboot)
	}

	phase = "verified"
	plan.Phase = "verified"
	observation = directoryjoin.RejoinObservation{
		CurrentName: "B", PendingName: "B", Domain: "corp.example", Netbios: "CORP", Role: "workstation",
		SecureChannel: "true", Boot: directoryjoin.BootObservation{Marker: "boot-b", Started: "2026-10-28T00:05:00Z"},
	}
	if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
		t.Fatalf("post-boot task join verification: %v", err)
	}
	marker, err = directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker == nil || marker.Phase != "verified" {
		t.Fatalf("task join was not verified: marker=%+v err=%v", marker, err)
	}
	if starts != 1 || joins != 1 || reports != 2 {
		t.Fatalf("task join duplicated or under-reported: starts=%d joins=%d reports=%d", starts, joins, reports)
	}
}
