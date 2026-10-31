package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

const directoryOperationTargetGUID = "22222222-2222-2222-2222-222222222222"

func directoryOperationPlan(operation, mode string) directoryjoin.RejoinPlan {
	p := directoryjoin.RejoinPlan{
		TaskID:          71,
		Version:         2,
		Operation:       operation,
		AttemptID:       strings.Repeat("a", 32),
		HostID:          71,
		ConfigRevision:  strings.Repeat("b", 32),
		Phase:           "ready",
		Name:            "B",
		Domain:          "corp.example",
		Mode:            mode,
		DC:              "dc.corp.example",
		ExpectedCurrent: "A",
		ExpectedPending: "B",
	}
	if operation == "rebind" {
		p.ExpectedPending = "A"
	}
	if mode == "existing" {
		p.Target = &directoryjoin.RejoinObject{
			GUID:    directoryOperationTargetGUID,
			SID:     "S-1-5-21-71-2",
			Account: "B$",
		}
	} else if operation == "rename" {
		p.Target = &directoryjoin.RejoinObject{
			GUID:    directoryOperationTargetGUID,
			SID:     "S-1-5-21-71-2",
			Account: p.ExpectedCurrent + "$",
		}
	}
	return p
}

func TestDirectoryOperationV2PlanDecodeValidateAndSourceOmission(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		mode      string
	}{
		{"existing rebind", "rebind", "existing"},
		{"ready create", "rebind", "create"},
		{"rename", "rename", "rename"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := directoryOperationPlan(tc.operation, tc.mode)
			encoded, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(`"source"`)) {
				t.Fatalf("v2 plan contains source field: %s", encoded)
			}
			var got directoryjoin.RejoinPlan
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if got.Version != 2 || got.Operation != tc.operation || got.Validate(got.HostID) != nil {
				t.Fatalf("decoded operation plan invalid: %+v", got)
			}
		})
	}
}

func TestDirectoryOperationV2ValidationRejectsInvalidSelectors(t *testing.T) {
	cases := map[string]func(*directoryjoin.RejoinPlan){
		"unknown version":        func(p *directoryjoin.RejoinPlan) { p.Version = 3 },
		"unknown operation":      func(p *directoryjoin.RejoinPlan) { p.Operation = "repair" },
		"rebind mode mismatch":   func(p *directoryjoin.RejoinPlan) { p.Mode = "rename" },
		"existing target absent": func(p *directoryjoin.RejoinPlan) { p.Target = nil },
		"create target on ready": func(p *directoryjoin.RejoinPlan) {
			p.Mode = "create"
			p.Target = &directoryjoin.RejoinObject{GUID: directoryOperationTargetGUID, SID: "S-1-5-21-71-2", Account: "B$"}
		},
		"rename pending conflict": func(p *directoryjoin.RejoinPlan) { p.ExpectedPending = "C" },
		"rename invalid current":  func(p *directoryjoin.RejoinPlan) { p.ExpectedCurrent = "123" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			plan := directoryOperationPlan("rename", "rename")
			if name == "existing target absent" {
				plan = directoryOperationPlan("rebind", "existing")
			}
			if name == "create target on ready" {
				plan = directoryOperationPlan("rebind", "create")
			}
			if name == "rebind mode mismatch" {
				plan = directoryOperationPlan("rebind", "existing")
			}
			mutate(&plan)
			if err := plan.Validate(plan.HostID); err == nil {
				t.Fatal("invalid v2 selector was accepted")
			}
		})
	}
}

func TestDirectoryOperationStartRequestAndResponseBinding(t *testing.T) {
	for _, operation := range []string{"rebind", "rename"} {
		t.Run(operation, func(t *testing.T) {
			plan := directoryOperationPlan(operation, map[string]string{"rebind": "existing", "rename": "rename"}[operation])
			var request map[string]any
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/agent/v1/directory/rejoin/start" {
					http.NotFound(w, r)
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": "ok",
					"directory": map[string]any{
						"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": true,
						"rejoin": plan,
					},
				})
			}))
			defer server.Close()

			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			policy, err := client.StartRejoin(context.Background(), plan)
			if err != nil {
				t.Fatalf("start rejoin: %v", err)
			}
			defer policy.Password.Zero()
			if request["operation"] != operation || request["attempt_id"] != plan.AttemptID || request["config_revision"] != plan.ConfigRevision || request["task_id"] != float64(plan.TaskID) {
				t.Fatalf("v2 operation selector not bound in request: %#v", request)
			}
			if _, ok := request["source"]; ok {
				t.Fatalf("start request exposed source: %#v", request)
			}
		})
	}
}

func TestDirectoryOperationStartRejectsChangedOperationBinding(t *testing.T) {
	for _, field := range []string{"operation", "expected_current", "expected_pending"} {
		t.Run(field, func(t *testing.T) {
			plan := directoryOperationPlan("rename", "rename")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				changed := plan
				switch field {
				case "operation":
					changed.Operation = "rebind"
				case "expected_current":
					changed.ExpectedCurrent = "C"
				case "expected_pending":
					changed.ExpectedPending = "C"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
					"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": true, "rejoin": changed,
				}})
			}))
			defer server.Close()
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
			if policy, err := client.StartRejoin(context.Background(), plan); err == nil {
				policy.Password.Zero()
				t.Fatal("changed operation binding accepted")
			}
		})
	}
}

func TestDirectoryOperationLifecycleNativeExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		mode      string
	}{
		{"D2-existing", "rebind", "existing"},
		{"D1-create", "rebind", "create"},
		{"workgroup-join", "join", "join"},
		{"D3-rename", "rename", "rename"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := directoryOperationPlan(tc.operation, tc.mode)
			if tc.operation == "join" {
				plan.ExpectedCurrent = plan.Name
				plan.ExpectedPending = plan.Name
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
			starts, rebinds, joins, renames := 0, 0, 0, 0
			reports := make(map[string]int)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/agent/v1/directory/rejoin/start":
					starts++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode start request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if body["operation"] != tc.operation || body["attempt_id"] != plan.AttemptID || body["config_revision"] != plan.ConfigRevision || body["task_id"] != float64(plan.TaskID) {
						t.Errorf("wrong start request: %#v", body)
					}
					if _, ok := body["source"]; ok {
						t.Error("source appeared on v2 start wire")
					}
					if phase != "ready" {
						w.WriteHeader(http.StatusConflict)
						_ = json.NewEncoder(w).Encode(map[string]any{"status": "blocked"})
						return
					}
					phase = "started"
					rebootPolicy := tc.operation == "join"
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
						"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": rebootPolicy, "rejoin": plan,
					}})
				case "/agent/v1/result":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode result request: %v", err)
					}
					item, _ := body["item"].(map[string]any)
					if item["task_id"] != float64(plan.TaskID) {
						t.Errorf("result task binding missing: %#v", item)
					}
					status, _ := item["status"].(string)
					reports[status]++
					if item["status"] == "verified" && item["netbios"] != "CORP" {
						t.Errorf("verified Netbios missing from result: %#v", item)
					}
					if item["status"] == "awaiting_reboot" || item["status"] == "verified" {
						if item["native_status"] != float64(0) {
							t.Errorf("success result lacked exact native zero: %#v", item)
						}
					}
					if item["status"] == "verified" && item["boot_changed"] != true {
						t.Error("verified report lacked changed boot")
					}
					if item["status"] == "verified" {
						phase = "verified"
					} else if item["status"] == "awaiting_reboot" {
						phase = "awaiting_reboot"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}

			boot := directoryjoin.BootObservation{Marker: "boot-a", Started: "2026-10-25T00:00:00Z"}
			secureChannel := "true"
			if tc.operation == "rename" {
				secureChannel = "false"
			}
			initialDomain := plan.Domain
			if tc.operation == "join" {
				initialDomain = ""
			}
			observation := directoryjoin.RejoinObservation{CurrentName: plan.ExpectedCurrent, PendingName: plan.ExpectedPending, Domain: initialDomain, Role: "workstation", SecureChannel: secureChannel, Boot: boot}
			oldObserve, oldRebind, oldJoin, oldRename, oldSetName := observeRejoin, rebindDirectory, joinDirectory, renameDirectory, setRejoinName
			t.Cleanup(func() {
				observeRejoin, rebindDirectory, joinDirectory, renameDirectory, setRejoinName = oldObserve, oldRebind, oldJoin, oldRename, oldSetName
			})
			observeRejoin = func(string) (directoryjoin.RejoinObservation, error) { return observation, nil }
			setRejoinName = func(name string) error { observation.PendingName = name; return nil }
			rebindDirectory = func(_ context.Context, _ directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
				rebinds++
				if got.Operation != "rebind" {
					t.Errorf("native rebind received operation %q", got.Operation)
				}
				return 0, nil
			}
			renameDirectory = func(_ context.Context, _ directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
				renames++
				if got.Operation != "rename" {
					t.Errorf("native rename received operation %q", got.Operation)
				}
				return 0, nil
			}
			joinDirectory = func(_ context.Context, policy directoryjoin.Policy, got directoryjoin.RejoinPlan) (uint32, error) {
				joins++
				if got.Operation != "join" || got.Mode != "join" || !policy.Reboot {
					t.Errorf("native join received wrong plan or reboot policy: plan=%+v reboot=%t", got, policy.Reboot)
				}
				return 0, nil
			}

			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
				t.Fatalf("first operation pass: %v", err)
			}
			plan.Phase = phase
			if tc.mode == "create" {
				plan.Target = &directoryjoin.RejoinObject{
					GUID: directoryOperationTargetGUID, SID: "S-1-5-21-71-2", Account: "B$",
				}
			}
			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
				t.Fatalf("same-boot operation pass: %v", err)
			}
			if tc.operation != "rename" {
				observation = directoryjoin.RejoinObservation{
					CurrentName: plan.Name, PendingName: plan.Name, Domain: plan.Domain, Netbios: "CORP", Role: "workstation", SecureChannel: "false",
					Boot: directoryjoin.BootObservation{Marker: "boot-b", Started: "2026-10-25T00:05:00Z"},
				}
				plan.Phase = phase
				if len(st.Config.PendingReboot) != 1 || st.Config.PendingReboot[0].Source != "directory-rejoin" {
					t.Fatalf("native success did not queue one directory reboot reason: %+v", st.Config.PendingReboot)
				}
				queuedReason := st.Config.PendingReboot[0]
				for poll := 1; poll <= 2; poll++ {
					if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil || !strings.Contains(err.Error(), "not healthy") {
						t.Fatalf("post-boot false secure channel poll %d error = %v, want read-only pending verification", poll, err)
					}
					marker, err := directoryjoin.LoadAttempt(st.Dir)
					if err != nil || marker == nil || marker.Phase != "awaiting_reboot" {
						t.Fatalf("post-boot false secure channel poll %d lost pending marker: marker=%+v err=%v", poll, marker, err)
					}
					if reports["verified"] != 0 {
						t.Fatalf("post-boot false secure channel reported verified during poll %d: reports=%v", poll, reports)
					}
					if len(st.Config.PendingReboot) != 1 || st.Config.PendingReboot[0] != queuedReason {
						t.Fatalf("post-boot false secure channel duplicated or changed reboot reason at poll %d: before=%+v after=%+v", poll, queuedReason, st.Config.PendingReboot)
					}
					wantRebind, wantJoin := 1, 0
					if tc.operation == "join" {
						wantRebind, wantJoin = 0, 1
					}
					if starts != 1 || rebinds != wantRebind || joins != wantJoin || renames != 0 {
						t.Fatalf("post-boot false secure channel replayed native operation at poll %d: starts=%d rebind=%d join=%d rename=%d", poll, starts, rebinds, joins, renames)
					}
				}
				phase = "awaiting_reboot"
			} else {
				observation = directoryjoin.RejoinObservation{
					CurrentName: "B", PendingName: "B", Domain: plan.Domain, Netbios: "CORP", Role: "workstation", SecureChannel: "false",
					Boot: directoryjoin.BootObservation{Marker: "boot-b", Started: "2026-10-25T00:05:00Z"},
				}
				plan.Phase = phase
				if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil || !strings.Contains(err.Error(), "not healthy") {
					t.Fatalf("post-boot false secure channel error = %v, want read-only pending verification", err)
				}
				marker, err := directoryjoin.LoadAttempt(st.Dir)
				if err != nil || marker == nil || marker.Phase != "awaiting_reboot" {
					t.Fatalf("post-boot false secure channel lost pending marker: marker=%+v err=%v", marker, err)
				}
				if renames != 1 || rebinds != 0 || joins != 0 {
					t.Fatalf("post-boot false secure channel replayed/fell back: rename=%d rebind=%d join=%d", renames, rebinds, joins)
				}
				phase = "awaiting_reboot"
			}
			plan.Phase = phase
			observation = directoryjoin.RejoinObservation{
				CurrentName: plan.Name, PendingName: plan.Name, Domain: plan.Domain, Netbios: "CORP", Role: "workstation", SecureChannel: "true",
				Boot: directoryjoin.BootObservation{Marker: "boot-b", Started: "2026-10-25T00:05:00Z"},
			}
			if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
				t.Fatalf("post-boot verification pass: %v", err)
			}
			wantRebind, wantJoin, wantRename := 1, 0, 0
			if tc.operation == "join" {
				wantRebind, wantJoin = 0, 1
			}
			if tc.operation == "rename" {
				wantRebind, wantRename = 0, 1
			}
			if starts != 1 || rebinds != wantRebind || joins != wantJoin || renames != wantRename {
				t.Fatalf("operation replayed or selected wrong native call: starts=%d rebind=%d join=%d rename=%d", starts, rebinds, joins, renames)
			}
			if reports["verified"] != 1 {
				t.Fatalf("healthy post-boot recovery reported verified %d times, want exactly once: reports=%v", reports["verified"], reports)
			}
			marker, err := directoryjoin.LoadAttempt(st.Dir)
			if err != nil || marker == nil || marker.Phase != "verified" || marker.Version != 2 || marker.Plan.Operation != tc.operation {
				t.Fatalf("v2 marker did not retain operation/phase: marker=%+v err=%v", marker, err)
			}
		})
	}
}

func TestDirectoryOperationLegacyRenameWithoutPinnedTargetStopsBeforeClaim(t *testing.T) {
	plan := directoryOperationPlan("rename", "rename")
	plan.Target = nil // Completed legacy plans remain readable, but cannot start a rename.
	if err := plan.Validate(plan.HostID); err != nil {
		t.Fatalf("legacy rename plan shape should remain decodable: %v", err)
	}
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = plan.HostID
	natives := 0
	oldRebind, oldRename := rebindDirectory, renameDirectory
	t.Cleanup(func() { rebindDirectory, renameDirectory = oldRebind, oldRename })
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	renameDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, nil, &plan, &sayer{}); err == nil {
		t.Fatal("rename without the old directory object identity was accepted")
	}
	marker, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker != nil {
		t.Fatalf("legacy rename plan reserved an attempt before identity preflight: marker=%+v err=%v", marker, err)
	}
	if natives != 0 {
		t.Fatalf("legacy rename plan reached a native operation: calls=%d", natives)
	}
}

func TestDirectoryOperationUnknownMarkerNeverFallsBackOrReplays(t *testing.T) {
	plan := directoryOperationPlan("rename", "rename")
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = plan.HostID
	fp, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: plan, Phase: "unknown"}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}

	starts, reports, natives := 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			starts++
		case "/agent/v1/result":
			reports++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode unknown report: %v", err)
			}
			item, _ := body["item"].(map[string]any)
			if item["status"] != "unknown" {
				t.Errorf("unknown marker reported as another phase: %#v", item)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
	oldRebind, oldRename := rebindDirectory, renameDirectory
	t.Cleanup(func() { rebindDirectory, renameDirectory = oldRebind, oldRename })
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	renameDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err == nil {
		t.Fatal("unknown marker unexpectedly resumed")
	}
	got, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || got == nil || got.Phase != "unknown" {
		t.Fatalf("unknown marker was changed: marker=%+v err=%v", got, err)
	}
	if starts != 0 || reports != 1 || natives != 0 {
		t.Fatalf("unknown marker fell back or replayed: starts=%d reports=%d native=%d", starts, reports, natives)
	}
}

func TestDirectoryOperationNewAttemptDoesNotEraseUnresolvedV2Marker(t *testing.T) {
	oldPlan := directoryOperationPlan("rename", "rename")
	oldPlan.AttemptID = strings.Repeat("c", 32)
	oldPlan.ConfigRevision = strings.Repeat("d", 32)
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = oldPlan.HostID
	fp, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	marker := &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: oldPlan, Phase: "unknown"}
	if err := directoryjoin.ReserveAttempt(st.Dir, marker); err != nil {
		t.Fatal(err)
	}
	path := directoryjoin.AttemptPath(st.Dir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	newPlan := directoryOperationPlan("rename", "rename")
	starts, natives := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/v1/directory/rejoin/start" {
			starts++
		}
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
	oldRebind, oldRename := rebindDirectory, renameDirectory
	t.Cleanup(func() { rebindDirectory, renameDirectory = oldRebind, oldRename })
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	renameDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, client, &newPlan, &sayer{}); err == nil {
		t.Fatal("new v2 attempt replaced an unresolved marker without retry authorization")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || got == nil || got.Plan.AttemptID != oldPlan.AttemptID || got.Plan.ConfigRevision != oldPlan.ConfigRevision || got.Phase != "unknown" {
		t.Fatalf("unresolved v2 marker changed: marker=%+v err=%v", got, err)
	}
	if !bytes.Equal(before, after) || starts != 0 || natives != 0 {
		t.Fatalf("marker was rewritten or operation dispatched: sameBytes=%t starts=%d native=%d", bytes.Equal(before, after), starts, natives)
	}
}

func TestDirectoryOperationLegacyV1UnresolvedMarkerStopsWithoutReplay(t *testing.T) {
	oldPlan := directoryjoin.RejoinPlan{
		AttemptID: strings.Repeat("c", 32), HostID: 72, ConfigRevision: strings.Repeat("d", 32),
		Phase: "ready", Name: "B", Domain: "corp.example", Mode: "existing", DC: "dc.corp.example",
		Source: directoryjoin.RejoinObject{GUID: "11111111-1111-1111-1111-111111111111", SID: "S-1-5-21-72-1", Account: "A$"},
		Target: &directoryjoin.RejoinObject{GUID: directoryOperationTargetGUID, SID: "S-1-5-21-72-2", Account: "B$"},
	}
	for _, phase := range []string{"unknown", "awaiting_reboot"} {
		for _, withPlan := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/plan=%t", phase, withPlan), func(t *testing.T) {
				st, err := enroll.Load(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.EnsureKey(identity.Host{}); err != nil {
					t.Fatal(err)
				}
				st.Config.HostID = oldPlan.HostID
				fp, err := st.KeyFingerprint()
				if err != nil {
					t.Fatal(err)
				}
				if err := directoryjoin.ReserveAttempt(st.Dir, &directoryjoin.Attempt{Version: 1, Fingerprint: fp, Plan: oldPlan, Phase: phase}); err != nil {
					t.Fatal(err)
				}
				path := directoryjoin.AttemptPath(st.Dir)
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				starts, natives := 0, 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					starts++
					http.Error(w, "legacy operation must not start", http.StatusInternalServerError)
				}))
				defer server.Close()
				client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
				oldRebind := rebindDirectory
				t.Cleanup(func() { rebindDirectory = oldRebind })
				rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
					natives++
					return 0, nil
				}
				var plan *directoryjoin.RejoinPlan
				if withPlan {
					v2 := directoryOperationPlan("rebind", "existing")
					v2.HostID = oldPlan.HostID
					plan = &v2
				}
				if err := processRejoin(context.Background(), st, client, plan, &sayer{}); err == nil || !strings.Contains(err.Error(), "legacy directory operation requires review") {
					t.Fatalf("processRejoin error = %v, want legacy marker STOP", err)
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				got, err := directoryjoin.LoadAttempt(st.Dir)
				if err != nil || got == nil || got.Version != 1 || got.Phase != phase {
					t.Fatalf("legacy marker changed: marker=%+v err=%v", got, err)
				}
				if !bytes.Equal(before, after) || starts != 0 || natives != 0 {
					t.Fatalf("legacy marker replayed or changed: sameBytes=%t starts=%d native=%d", bytes.Equal(before, after), starts, natives)
				}
			})
		}
	}
}

func TestDirectoryOperationNativeFailurePhaseAndCodeAreStable(t *testing.T) {
	plan := directoryOperationPlan("rename", "rename")
	st, err := enroll.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(identity.Host{}); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = plan.HostID
	starts, natives, fallbacks, reports := 0, 0, 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/directory/rejoin/start":
			starts++
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "directory": map[string]any{
				"domain": plan.Domain, "username": `CORP\fixture`, "password": "test-secret", "reboot": false, "rejoin": plan,
			}})
		case "/agent/v1/result":
			reports++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode failed result: %v", err)
			}
			item, _ := body["item"].(map[string]any)
			if item["status"] != "failed" || item["native_status"] != float64(5) {
				t.Errorf("failure report changed phase/code: %#v", item)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &enroll.Client{ServerURL: server.URL, HTTP: server.Client()}
	oldObserve, oldRebind, oldRename, oldSetName := observeRejoin, rebindDirectory, renameDirectory, setRejoinName
	t.Cleanup(func() {
		observeRejoin, rebindDirectory, renameDirectory, setRejoinName = oldObserve, oldRebind, oldRename, oldSetName
	})
	observation := directoryjoin.RejoinObservation{CurrentName: plan.ExpectedCurrent, PendingName: plan.ExpectedPending, Domain: plan.Domain, Role: "workstation", SecureChannel: "false"}
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		return observation, nil
	}
	setRejoinName = func(name string) error { observation.PendingName = name; return nil }
	renameDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		natives++
		return 5, nil
	}
	rebindDirectory = func(context.Context, directoryjoin.Policy, directoryjoin.RejoinPlan) (uint32, error) {
		fallbacks++
		return 0, nil
	}
	if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
		t.Fatalf("native failure report: %v", err)
	}
	if err := processRejoin(context.Background(), st, client, &plan, &sayer{}); err != nil {
		t.Fatalf("retained failure report: %v", err)
	}
	marker, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil || marker == nil || marker.Phase != "failed" || marker.NativeStatus == nil || *marker.NativeStatus != 5 {
		t.Fatalf("failure marker phase/code changed: marker=%+v err=%v", marker, err)
	}
	if starts != 1 || natives != 1 || fallbacks != 0 || reports != 2 {
		t.Fatalf("failure was replayed or fell back: starts=%d rename=%d fallback=%d reports=%d", starts, natives, fallbacks, reports)
	}
}

func TestDirectoryOperationGoPHPSelectorContract(t *testing.T) {
	root := os.Getenv("MJ1_SERVER_ROOT")
	if root == "" {
		t.Skip("MJ1_SERVER_ROOT not set: Go/PHP operation contract")
	}
	fixture := filepath.Join(root, "tests", "fixtures", "directory-operation-contract.php")
	if _, err := os.Stat(fixture); errors.Is(err, os.ErrNotExist) {
		t.Skip("directory-operation-contract.php is not ready")
	} else if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		operation string
		mode      string
		deploy    bool
		secure    string
		confirmed bool
		create    bool
	}{
		{"D2-existing-deploy", "rebind", "existing", true, "false", true, false},
		{"D1-create-deploy", "rebind", "create", true, "false", false, true},
		{"D3-samehealthy-deploy", "rebind", "existing", true, "true", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secure, confirmed, allowCreate := tc.secure, tc.confirmed, false
			target := map[string]any{"status": "found", "record": map[string]any{
				"guid": directoryOperationTargetGUID, "sid": "S-1-5-21-71-2", "account": "B$",
			}}
			if tc.create {
				target, allowCreate = map[string]any{"status": "absent"}, true
			}
			input, err := json.Marshal(map[string]any{
				"action": "select", "name": "B", "deploy": tc.deploy, "reassigned": false,
				"target": target, "allow_create": allowCreate, "confirmed": confirmed, "authorized": true,
				"observation": map[string]any{"current_name": "A", "pending_name": "B", "role": "workstation", "dc_reachable": true, "secure_channel": secure},
			})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("php", fixture)
			cmd.Stdin = bytes.NewReader(input)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("PHP selector fixture: %v", err)
			}
			var result struct {
				Status string          `json:"status"`
				Data   json.RawMessage `json:"data"`
				Reason string          `json:"reason"`
			}
			if err := json.Unmarshal(out, &result); err != nil || result.Status != "ok" {
				t.Fatalf("PHP selector refused/invalid response: status=%q reason=%q err=%v body=%s", result.Status, result.Reason, err, out)
			}
			var selection struct {
				Operation string                      `json:"operation"`
				Mode      string                      `json:"mode"`
				Target    *directoryjoin.RejoinObject `json:"target"`
			}
			if err := json.Unmarshal(result.Data, &selection); err != nil {
				t.Fatalf("decode PHP selection: %v", err)
			}
			if selection.Operation != tc.operation || selection.Mode != tc.mode {
				t.Fatalf("PHP selected wrong operation: %+v", selection)
			}
		})
	}
}

func TestDirectoryOperationGoPHPFlow(t *testing.T) {
	root, dsn := os.Getenv("MJ1_SERVER_ROOT"), os.Getenv("MJ1_DB_DSN")
	if root == "" || dsn == "" {
		t.Skip("MJ1_SERVER_ROOT and MJ1_DB_DSN are required for Go/PHP operation flow")
	}
	fixture := filepath.Join(root, "tests", "fixtures", "directory-operation-flow.php")
	if _, err := os.Stat(fixture); err != nil {
		t.Fatalf("required directory operation flow fixture unavailable: %v", err)
	}
	cases := []struct {
		action            string
		name              string
		operation         string
		mode              string
		consumedTaskID    int
		checkConsumed     bool
		wantSameNameState bool
	}{
		{action: "rebind_create", name: "B", operation: "rebind", mode: "create"},
		{action: "rebind_existing", name: "B", operation: "rebind", mode: "existing"},
		{action: "rename_configured", name: "B", operation: "rename", mode: "rename"},
		{action: "self_restore", name: "B", operation: "rebind", mode: "existing", consumedTaskID: 500, checkConsumed: true, wantSameNameState: true},
		{action: "reassigned_rename", name: "C", operation: "rebind", mode: "create"},
		{action: "task_join", name: "B", operation: "join", mode: "join", consumedTaskID: 500, checkConsumed: true, wantSameNameState: true},
		{action: "healthy_self_restore", name: "B", operation: "rebind", mode: "existing", consumedTaskID: 500, checkConsumed: true, wantSameNameState: true},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			input, err := json.Marshal(map[string]string{"action": tc.action, "name": tc.name})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("php", fixture)
			cmd.Stdin = bytes.NewReader(input)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("PHP operation flow failed: %v; output: %s", err, out)
			}
			var result struct {
				Status         string          `json:"status"`
				Plan           json.RawMessage `json:"plan"`
				ResponsePlan   json.RawMessage `json:"response_plan"`
				SourceOmitted  bool            `json:"source_omitted"`
				StartClaimed   bool            `json:"start_claimed"`
				ReplayRefused  bool            `json:"replay_refused"`
				ReportedPhase  string          `json:"reported_phase"`
				Operation      string          `json:"operation"`
				Mode           string          `json:"mode"`
				ConsumedTaskID int             `json:"consumed_task_id"`
				Reason         string          `json:"reason"`
			}
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("invalid PHP operation flow JSON: %v; output: %s", err, out)
			}
			if result.Status != "ok" {
				t.Fatalf("PHP operation flow refused: %s; output: %s", result.Reason, out)
			}
			var plan, responsePlan directoryjoin.RejoinPlan
			if err := json.Unmarshal(result.Plan, &plan); err != nil {
				t.Fatalf("decode PHP public plan: %v", err)
			}
			if err := json.Unmarshal(result.ResponsePlan, &responsePlan); err != nil {
				t.Fatalf("decode PHP start response plan: %v", err)
			}
			if plan.Version != 2 || plan.Operation != tc.operation || plan.Mode != tc.mode || plan.Validate(7001) != nil {
				t.Fatalf("invalid PHP public v2 plan: %+v", plan)
			}
			if (result.Operation != "" && result.Operation != plan.Operation) || (result.Mode != "" && result.Mode != plan.Mode) {
				t.Fatalf("PHP flow operation/mode disagrees with plan: output=%+v plan=%+v", result, plan)
			}
			if tc.checkConsumed && result.ConsumedTaskID != tc.consumedTaskID {
				t.Fatalf("completed deploy task consumption mismatch: got=%d want=%d", result.ConsumedTaskID, tc.consumedTaskID)
			}
			if tc.wantSameNameState && (plan.ExpectedCurrent != tc.name || plan.ExpectedPending != tc.name) {
				t.Fatalf("self-restore did not bind current and pending name %q: current=%q pending=%q", tc.name, plan.ExpectedCurrent, plan.ExpectedPending)
			}
			if tc.action == "reassigned_rename" && (result.Operation != "rebind" || plan.Name != "C" || plan.Operation != "rebind" || plan.Mode != "create" || plan.Target != nil ||
				plan.ExpectedCurrent != "A" || plan.ExpectedPending != "A") {
				t.Fatalf("reassigned rename was not routed to literal C rebind/create from A: %+v", plan)
			}
			if !result.SourceOmitted || !result.StartClaimed || !result.ReplayRefused || result.ReportedPhase != "verified" {
				t.Fatalf("PHP flow lifecycle contract failed: %+v", result)
			}
			for label, raw := range map[string]json.RawMessage{"plan": result.Plan, "response_plan": result.ResponsePlan} {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					t.Fatalf("decode %s object: %v", label, err)
				}
				if _, ok := fields["source"]; ok {
					t.Errorf("%s included Source JSON", label)
				}
				if label == "response_plan" {
					if _, ok := fields["password"]; ok {
						t.Error("start response plan included a credential")
					}
					if _, ok := fields["username"]; ok {
						t.Error("start response plan included a credential principal")
					}
				}
			}
			if responsePlan.TaskID != plan.TaskID || responsePlan.Version != plan.Version || responsePlan.Operation != plan.Operation ||
				responsePlan.Mode != plan.Mode || responsePlan.HostID != plan.HostID ||
				responsePlan.AttemptID != plan.AttemptID || responsePlan.ConfigRevision != plan.ConfigRevision ||
				responsePlan.Name != plan.Name || responsePlan.Domain != plan.Domain || responsePlan.DC != plan.DC ||
				responsePlan.ExpectedCurrent != plan.ExpectedCurrent || responsePlan.ExpectedPending != plan.ExpectedPending ||
				responsePlan.RetryAuthorized != plan.RetryAuthorized || responsePlan.Validate(7001) != nil {
				t.Fatalf("start response plan binding differs: plan=%+v response=%+v", plan, responsePlan)
			}
			if (responsePlan.Target == nil) != (plan.Target == nil) || (plan.Target != nil &&
				(responsePlan.Target.GUID != plan.Target.GUID || responsePlan.Target.SID != plan.Target.SID || responsePlan.Target.Account != plan.Target.Account)) {
				t.Fatalf("start response Target binding differs: plan=%+v response=%+v", plan.Target, responsePlan.Target)
			}
		})
	}
}

func TestDirectoryCheckObservationCacheAndErrors(t *testing.T) {
	oldObserve, oldReachable := observeRejoin, directoryDCReachable
	t.Cleanup(func() { observeRejoin, directoryDCReachable = oldObserve, oldReachable })
	check := &enroll.DirectoryCheck{Name: "B", Domain: "corp.example", DC: "dc.corp.example", Revision: strings.Repeat("a", 32)}
	st := &enroll.State{
		DirectoryCheck: check,
		DirectoryObservation: &enroll.DirectoryObservation{
			RejoinObservation: directoryjoin.RejoinObservation{CurrentName: "B", PendingName: "B", Domain: "corp.example", SecureChannel: "true"},
			Revision:          check.Revision, DC: check.DC, DCReachable: true,
		},
		DirectoryObservedAt: time.Now(),
	}
	observes := 0
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observes++
		return directoryjoin.RejoinObservation{}, nil
	}
	directoryDCReachable = func(string) bool { return true }
	if changed, err := refreshDirectoryCheck(st, check); err != nil || changed || observes != 0 {
		t.Fatalf("fresh matching observation was not reused: changed=%t observes=%d err=%v", changed, observes, err)
	}

	st.DirectoryObservedAt = time.Now().Add(-6 * time.Minute)
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observes++
		return directoryjoin.RejoinObservation{}, errors.New("observation unavailable")
	}
	if changed, err := refreshDirectoryCheck(st, check); err == nil || changed || st.DirectoryObservation != nil {
		t.Fatalf("stale observation survived refresh error: changed=%t cached=%+v err=%v", changed, st.DirectoryObservation, err)
	}

	check.Revision = strings.Repeat("b", 32)
	observeRejoin = func(string) (directoryjoin.RejoinObservation, error) {
		observes++
		return directoryjoin.RejoinObservation{CurrentName: "B", PendingName: "B", Domain: "other.example", SecureChannel: "true"}, nil
	}
	directoryDCReachable = func(string) bool { return false }
	if changed, err := refreshDirectoryCheck(st, check); err != nil || !changed || st.DirectoryObservation == nil {
		t.Fatalf("new observation context was not refreshed: changed=%t cached=%+v err=%v", changed, st.DirectoryObservation, err)
	}
	if st.DirectoryObservation.Revision != check.Revision || st.DirectoryObservation.DCReachable || st.DirectoryObservation.SecureChannel != "unknown" {
		t.Fatalf("stale or untrusted observation accepted: %+v", st.DirectoryObservation)
	}
}
