package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
)

func mj1TLSClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	caPEM, serverCert, serverKey, _, _ := testCA(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
	}
	srv.StartTLS()
	client, err := NewClient(srv.URL, caPEM)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return client, srv
}

func TestRequireMJ1StopsOnOldServerOrMissingFeatureHeader(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		header  string
		wantOK  bool
		wantErr error
	}{
		{"old server route", http.StatusNotFound, "", false, ErrDirectoryFeaturesUnsupported},
		{"missing feature header", http.StatusOK, "", false, ErrDirectoryFeaturesUnsupported},
		{"temporarily unavailable", http.StatusServiceUnavailable, "", false, ErrDirectoryFeaturesUnavailable},
		{"temporarily rate limited", http.StatusTooManyRequests, "", false, ErrDirectoryFeaturesUnavailable},
		{"new identity feature only", http.StatusOK, DirectoryJoinTargetFeature, false, ErrDirectoryFeaturesUnsupported},
		{"both comma separated", http.StatusOK, DirectoryJoinTargetFeature + ", " + DirectoryTaskOperationsFeature, true, nil},
		{"new task operations feature v1", http.StatusOK, DirectoryJoinTargetFeature + ", directory-task-operations-v1", true, nil},
		{"legacy feature pair rejected", http.StatusOK, "directory-join-mj1, directory-task-operations-v3", false, ErrDirectoryFeaturesUnsupported},
		{"legacy identity with new task feature rejected", http.StatusOK, "directory-join-mj1, " + DirectoryTaskOperationsFeature, false, ErrDirectoryFeaturesUnsupported},
		{"new identity with legacy task feature rejected", http.StatusOK, DirectoryJoinTargetFeature + ", directory-task-operations-v3", false, ErrDirectoryFeaturesUnsupported},
		{"old target feature v2 rejected", http.StatusOK, DirectoryJoinTargetFeature + ", directory-join-target-v2", false, ErrDirectoryFeaturesUnsupported},
		{"both space separated", http.StatusOK, DirectoryJoinTargetFeature + " " + DirectoryTaskOperationsFeature, true, nil},
		{"extra capability and reordered", http.StatusOK, "future-capability " + DirectoryTaskOperationsFeature + ", " + DirectoryJoinTargetFeature, true, nil},
		{"identity substring is not a token", http.StatusOK, "x-" + DirectoryJoinTargetFeature + ", " + DirectoryTaskOperationsFeature, false, ErrDirectoryFeaturesUnsupported},
		{"task feature substring is not a token", http.StatusOK, DirectoryJoinTargetFeature + ", " + DirectoryTaskOperationsFeature + "-preview", false, ErrDirectoryFeaturesUnsupported},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			client, srv := mj1TLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/agent/v1/enroll" {
					t.Errorf("feature probe request = %s %s", r.Method, r.URL.Path)
				}
				if tt.header != "" {
					w.Header().Set("X-FOG-Agent-Features", tt.header)
				}
				w.WriteHeader(tt.status)
			}))
			err := client.RequireDirectoryFeatures(context.Background())
			if (err == nil) != tt.wantOK || (tt.wantErr != nil && !errors.Is(err, tt.wantErr)) {
				t.Fatalf("RequireDirectoryFeatures() error = %v, want success=%t", err, tt.wantOK)
			}
			if calls != 1 {
				t.Fatalf("feature probe made %d requests, want exactly one (%s)", calls, srv.URL)
			}
		})
	}
}

func TestCheckIdentityAcceptsOnlyMatchedOrExplicitMismatch(t *testing.T) {
	cases := []struct {
		name       string
		code       int
		status     string
		idStatus   string
		hostID     int
		principal  int
		wantStatus string
		wantErr    bool
	}{
		{"matched", 200, "ok", "matched", 12, 12, "matched", false},
		{"explicit mismatch", 409, "identity_blocked", "mismatch", 13, 12, "mismatch", false},
		{"conflict", 409, "identity_blocked", "conflict", 13, 12, "", true},
		{"forged mismatch status", 200, "ok", "mismatch", 13, 12, "", true},
		{"matched host differs from principal", 200, "ok", "matched", 13, 12, "", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := mj1TLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/identity/check" {
					t.Errorf("identity request = %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.code)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": tt.status,
					"identity": map[string]any{
						"status": tt.idStatus, "host_id": tt.hostID,
						"principal_host_id": tt.principal,
					},
				})
			}))
			answer, err := client.CheckIdentity(context.Background(), identity.Host{})
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckIdentity() error = %v, want error=%t", err, tt.wantErr)
			}
			if !tt.wantErr && answer.Identity.Status != tt.wantStatus {
				t.Fatalf("identity status = %q, want %q", answer.Identity.Status, tt.wantStatus)
			}
		})
	}
}

func TestStartRejoinBindingMismatchRedactsCredential(t *testing.T) {
	const password = "must-never-appear-in-errors"
	plan := directoryjoin.RejoinPlan{
		Version:         2,
		Operation:       "rebind",
		ExpectedCurrent: "OLDNAME",
		ExpectedPending: "WORKSTATION",
		AttemptID:       strings.Repeat("a", 32),
		HostID:          12,
		ConfigRevision:  strings.Repeat("b", 32),
		Name:            "WORKSTATION",
		Domain:          "corp.example.com",
		Mode:            "existing",
		DC:              "dc01.corp.example.com",
		Target: &directoryjoin.RejoinObject{
			Account: "WORKSTATION$",
		},
		TaskID: 42,
	}
	changed := plan
	changed.ConfigRevision = strings.Repeat("c", 32)
	client, _ := mj1TLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/directory/rejoin/start" {
			t.Errorf("rejoin start request = %s %s", r.Method, r.URL.Path)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["task_id"] != float64(42) {
			t.Errorf("start request task_id = %#v, decode err = %v", request["task_id"], err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"directory": map[string]any{
				"domain": plan.Domain, "username": `CORP\join`,
				"password": password, "reboot": true, "rejoin": changed,
			},
		})
	}))
	_, err := client.StartRejoin(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "binding changed") {
		t.Fatalf("changed binding error = %v", err)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("binding error exposed the server credential: %v", err)
	}
}

func TestStartRejoinRejectsTaskIDMismatch(t *testing.T) {
	plan := validMJ1PlanForHost(12)
	plan.Version = 2
	plan.Operation = "rebind"
	plan.ExpectedCurrent = "OLDNAME"
	plan.ExpectedPending = "WORKSTATION"
	plan.TaskID = 42
	client, _ := mj1TLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["task_id"] != float64(42) {
			t.Errorf("start request task_id = %#v, decode err = %v", request["task_id"], err)
		}
		reply, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		var rejoin map[string]any
		if err = json.Unmarshal(reply, &rejoin); err != nil {
			t.Fatal(err)
		}
		rejoin["task_id"] = 43
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"directory": map[string]any{
				"domain": plan.Domain, "username": `CORP\join`, "password": "secret", "reboot": true, "rejoin": rejoin,
			},
		})
	}))
	policy, err := client.StartRejoin(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "operation binding changed") {
		t.Fatalf("task mismatch error = %v, want operation binding failure", err)
	}
	if policy != nil {
		policy.Password.Zero()
		t.Fatal("task mismatch returned a usable rejoin policy")
	}
}

func TestRotateIdentityPreservesTrustAndClearsOldIdentityWithoutCloneClassification(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(liveID("old-machine")); err != nil {
		t.Fatal(err)
	}
	oldFingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	st.Config.ServerURL = "https://fog.example.test/fog"
	st.Config.SystemTrust = true
	st.Config.PendingToken = "pending-enrollment"
	st.Config.HostID = 101
	st.Config.AppliedRevision = "old-revision"
	st.Config.InventoryHash = "old-inventory"
	if err := st.SaveIssued([]byte("old-issued-certificate"), 101); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveConfig(); err != nil {
		t.Fatal(err)
	}

	attempt := &directoryjoin.Attempt{
		Version: 1, Fingerprint: oldFingerprint,
		Plan: validMJ1PlanForHost(101), Phase: "verified",
	}
	if err := directoryjoin.ReserveAttempt(dir, attempt); err != nil {
		t.Fatal(err)
	}

	if err := st.RotateIdentity(liveID("new-machine")); err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	newFingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if newFingerprint == oldFingerprint {
		t.Fatal("identity rotation retained the previous private key")
	}
	if st.Config.ServerURL != "https://fog.example.test/fog" || !st.Config.SystemTrust {
		t.Fatalf("rotation lost server trust configuration: URL=%q systemTrust=%t", st.Config.ServerURL, st.Config.SystemTrust)
	}
	if st.Config.HostID != 0 || st.Config.AppliedRevision != "" || st.Config.InventoryHash != "" || st.Cert != nil {
		t.Fatalf("rotation retained old host-bound data: config=%+v cert=%q", st.Config, st.Cert)
	}
	assertNoCloneClassification(t, st.Config)
	if _, err := os.Stat(filepath.Join(dir, certFile)); !os.IsNotExist(err) {
		t.Fatalf("old issued certificate still exists: %v", err)
	}
	if _, err := os.Stat(directoryjoin.AttemptPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("matching old rejoin marker still exists: %v", err)
	}
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Config.ServerURL != st.Config.ServerURL || !reloaded.Config.SystemTrust ||
		reloaded.Config.HostID != 0 || reloaded.Config.AppliedRevision != "" ||
		reloaded.Cert != nil {
		t.Fatalf("rotation result was not persisted safely: config=%+v cert=%q", reloaded.Config, reloaded.Cert)
	}
	assertNoCloneClassification(t, reloaded.Config)
}

func TestRotateIdentityPreservesMatchingUnknownLegacyMarker(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureKey(liveID("old-machine")); err != nil {
		t.Fatal(err)
	}
	oldFingerprint, err := st.KeyFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = 101
	attempt := &directoryjoin.Attempt{
		Version: 1, Fingerprint: oldFingerprint,
		Plan: validMJ1PlanForHost(101), Phase: "unknown",
	}
	if err := directoryjoin.ReserveAttempt(dir, attempt); err != nil {
		t.Fatal(err)
	}
	markerPath := directoryjoin.AttemptPath(dir)
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.RotateIdentity(liveID("new-machine")); err != nil {
		t.Fatalf("RotateIdentity: %v", err)
	}
	after, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("unknown marker was removed: %v", err)
	}
	got, err := directoryjoin.LoadAttempt(dir)
	if err != nil || got == nil || got.Version != 1 || got.Phase != "unknown" || got.Fingerprint != oldFingerprint || got.Plan.HostID != 101 {
		t.Fatalf("unknown legacy marker no longer loads unchanged: marker=%+v err=%v", got, err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("identity rotation rewrote the unknown legacy marker")
	}
}

func TestExplicitResetDoesNotInventCloneSource(t *testing.T) {
	st, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.EnsureKey(liveID("same-machine")); err != nil {
		t.Fatal(err)
	}
	st.Config.HostID = 7
	st.Config.SystemTrust = true
	if err = st.RotateIdentity(liveID("same-machine")); err != nil {
		t.Fatal(err)
	}
	if st.Config.HostID != 0 || !st.Config.SystemTrust {
		t.Fatalf("reset retained host data or lost trust: %+v", st.Config)
	}
	assertNoCloneClassification(t, st.Config)
}

func TestLegacyCloneConfigFieldsAreIgnoredAndNotReserialized(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"server_url":"https://fog.example.test/fog","system_trust":true,"clone_status":"detected","clone_origin":{"host_id":101}}`
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Config.ServerURL != "https://fog.example.test/fog" || !st.Config.SystemTrust {
		t.Fatalf("legacy config fields damaged supported settings: %+v", st.Config)
	}
	if err := st.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), "clone_status") || strings.Contains(string(onDisk), "clone_origin") {
		t.Fatalf("removed classification fields were reserialized: %s", onDisk)
	}
}

func TestTaskIDFromJSONRequiresNonnegativeInteger(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want int
		bad  bool
	}{
		{name: "zero", json: `{"task_id":0}`, want: 0},
		{name: "positive", json: `{"task_id":17}`, want: 17},
		{name: "missing", json: `{}`, bad: true},
		{name: "null", json: `{"task_id":null}`, bad: true},
		{name: "boolean", json: `{"task_id":true}`, bad: true},
		{name: "negative", json: `{"task_id":-1}`, bad: true},
		{name: "fraction", json: `{"task_id":1.5}`, bad: true},
		{name: "string", json: `{"task_id":"17"}`, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := taskIDFromJSON([]byte(tc.json))
			if tc.bad {
				if err == nil {
					t.Fatalf("taskIDFromJSON(%s) = %d, want error", tc.json, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("taskIDFromJSON(%s) = %d, %v; want %d, nil", tc.json, got, err, tc.want)
			}
		})
	}
}

func TestDirectoryTaskDTOFieldsDecode(t *testing.T) {
	var response PollResponse
	if err := json.Unmarshal([]byte(`{"directory_hold":true}`), &response); err != nil {
		t.Fatal(err)
	}
	if !response.DirectoryHold {
		t.Fatal("directory_hold was not decoded")
	}
	var item ResultItem
	if err := json.Unmarshal([]byte(`{"netbios":"CORP","task_id":23}`), &item); err != nil {
		t.Fatal(err)
	}
	if item.Netbios != "CORP" || item.TaskID != 23 {
		t.Fatalf("directory result bindings = netbios %q task %d", item.Netbios, item.TaskID)
	}
	responseJSON, err := json.Marshal(PollResponse{})
	if err != nil {
		t.Fatal(err)
	}
	var responseFields map[string]json.RawMessage
	if err := json.Unmarshal(responseJSON, &responseFields); err != nil {
		t.Fatal(err)
	}
	if _, ok := responseFields["directory_hold"]; !ok {
		t.Fatalf("directory_hold missing from DTO JSON: %s", responseJSON)
	}
	if string(responseFields["directory_hold"]) != "false" {
		t.Fatalf("zero-value directory_hold was not emitted as false: %s", responseJSON)
	}
	itemJSON, err := json.Marshal(ResultItem{})
	if err != nil {
		t.Fatal(err)
	}
	var itemFields map[string]json.RawMessage
	if err := json.Unmarshal(itemJSON, &itemFields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"task_id", "netbios"} {
		if _, ok := itemFields[field]; !ok {
			t.Fatalf("%s missing from DTO JSON: %s", field, itemJSON)
		}
	}
	for label, fields := range map[string]map[string]json.RawMessage{"poll response": responseFields, "result item": itemFields} {
		for _, field := range []string{"clone_status", "clone_origin"} {
			if _, ok := fields[field]; ok {
				t.Fatalf("%s contains removed clone classification %q", label, field)
			}
		}
	}
}

func assertNoCloneClassification(t *testing.T, config Config) {
	t.Helper()
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "clone_status") || strings.Contains(string(b), "clone_origin") {
		t.Fatalf("removed classification fields serialized: %s", b)
	}
}

func TestMJ1UnavailablePreservesOfflineSetupDistinction(t *testing.T) {
	c, srv := mj1TLSClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	if err := c.RequireDirectoryFeatures(context.Background()); err == nil || errors.Is(err, ErrDirectoryFeaturesUnavailable) {
		t.Fatalf("unsupported server treated as offline: %v", err)
	}
	srv.Close()
	if err := c.RequireDirectoryFeatures(context.Background()); !errors.Is(err, ErrDirectoryFeaturesUnavailable) {
		t.Fatalf("unreachable server classification: %v", err)
	}
}

func validMJ1PlanForHost(hostID int) directoryjoin.RejoinPlan {
	return directoryjoin.RejoinPlan{
		AttemptID: strings.Repeat("a", 32), HostID: hostID,
		ConfigRevision: strings.Repeat("b", 32), Name: "WORKSTATION",
		Domain: "corp.example.com", Mode: "existing", DC: "dc01.corp.example.com",
		Source: directoryjoin.RejoinObject{GUID: "11111111-1111-1111-1111-111111111111", SID: "S-1-5-21-1", Account: "SOURCE$"},
		Target: &directoryjoin.RejoinObject{GUID: "22222222-2222-2222-2222-222222222222", SID: "S-1-5-21-2", Account: "WORKSTATION$"},
	}
}
