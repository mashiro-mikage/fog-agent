package directoryjoin

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func validMJ1Plan() RejoinPlan {
	target := &RejoinObject{
		GUID:    "22222222-2222-2222-2222-222222222222",
		SID:     "S-1-5-21-2",
		Account: "WORKSTATION$",
	}
	return RejoinPlan{
		AttemptID:      strings.Repeat("a", 32),
		HostID:         17,
		ConfigRevision: strings.Repeat("b", 32),
		Phase:          "planned",
		Name:           "WORKSTATION",
		Domain:         "corp.example.com",
		Mode:           "existing",
		DC:             "dc01.corp.example.com",
		Source: RejoinObject{
			GUID:    "11111111-1111-1111-1111-111111111111",
			SID:     "S-1-5-21-1",
			Account: "SOURCE$",
		},
		Target: target,
	}
}

func validMJ1Attempt() *Attempt {
	return &Attempt{
		Version:     1,
		Fingerprint: strings.Repeat("c", 64),
		Plan:        validMJ1Plan(),
		Phase:       "reserved",
		BeforeBoot: BootObservation{
			Marker:  "boot-a",
			Started: "2026-10-24T01:00:00Z",
		},
	}
}

func validV2Plan(operation, mode string) RejoinPlan {
	p := validMJ1Plan()
	p.Version = 2
	p.Operation = operation
	p.Mode = mode
	p.ExpectedCurrent = "OLDNAME"
	p.ExpectedPending = p.Name
	if operation == "rebind" {
		p.ExpectedCurrent = "OLDNAME"
		p.ExpectedPending = "OLDNAME"
	}
	if operation == "rename" {
		p.Target = nil
	}
	return p
}

func TestRejoinPlanValidateExistingAndCreate(t *testing.T) {
	existing := validMJ1Plan()
	if err := existing.Validate(existing.HostID); err != nil {
		t.Fatalf("valid existing plan rejected: %v", err)
	}

	create := validMJ1Plan()
	create.Mode = "create"
	create.Target = nil
	if err := create.Validate(create.HostID); err != nil {
		t.Fatalf("valid create plan rejected: %v", err)
	}
}

func TestRejoinPlanRejectsSourceEqualToTarget(t *testing.T) {
	plan := validMJ1Plan()
	plan.Source.GUID = plan.Target.GUID
	if err := plan.Validate(plan.HostID); err == nil {
		t.Fatal("existing plan accepted the same directory object as source and target")
	}
}

func TestV2PlanValidatesWithoutSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan RejoinPlan
	}{
		{"existing rebind", validV2Plan("rebind", "existing")},
		{"create ready", func() RejoinPlan { p := validV2Plan("rebind", "create"); p.Target = nil; p.Phase = "ready"; return p }()},
		{"create after result", func() RejoinPlan { p := validV2Plan("rebind", "create"); p.Phase = "verified"; return p }()},
		{"rename pending target", validV2Plan("rename", "rename")},
		{"rename pending current", func() RejoinPlan {
			p := validV2Plan("rename", "rename")
			p.ExpectedPending = p.ExpectedCurrent
			return p
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.plan.Source = RejoinObject{}
			if err := tc.plan.Validate(tc.plan.HostID); err != nil {
				t.Fatalf("valid v2 plan rejected: %v", err)
			}
		})
	}
}

func TestV2PlanRejectsInvalidOperationTargetAndExpectedNames(t *testing.T) {
	cases := map[string]func(*RejoinPlan){
		"unknown version":                  func(p *RejoinPlan) { p.Version = 3 },
		"unknown operation":                func(p *RejoinPlan) { p.Operation = "repair" },
		"mode mismatch":                    func(p *RejoinPlan) { p.Mode = "existing" },
		"existing target absent":           func(p *RejoinPlan) { p.Target = nil },
		"target account mismatch":          func(p *RejoinPlan) { p.Target.Account = "OTHER$" },
		"create target on ready":           func(p *RejoinPlan) { p.Mode = "create"; p.Phase = "ready" },
		"create target absent after ready": func(p *RejoinPlan) { p.Mode = "create"; p.Target = nil; p.Phase = "verified" },
		"all numeric current":              func(p *RejoinPlan) { p.ExpectedCurrent = "123" },
		"invalid pending":                  func(p *RejoinPlan) { p.ExpectedPending = "OTHER" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validV2Plan("rename", "rename")
			if name == "existing target absent" || name == "target account mismatch" || strings.HasPrefix(name, "create target") {
				p = validV2Plan("rebind", "existing")
			}
			if name == "create target on ready" || name == "create target absent after ready" {
				p.Phase = "verified"
			}
			mutate(&p)
			if err := p.Validate(p.HostID); err == nil {
				t.Fatal("invalid v2 plan accepted")
			}
		})
	}
}

func TestV2PlanJSONOmitsSourceAndKeepsExplicitVersion(t *testing.T) {
	p := validV2Plan("rename", "rename")
	p.Source = RejoinObject{GUID: "legacy-guid", SID: "legacy-sid"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["source"]; ok {
		t.Fatal("v2 JSON exposed legacy source metadata")
	}
	if string(fields["version"]) != "2" {
		t.Fatalf("v2 JSON version = %s, want 2", fields["version"])
	}
	var got RejoinPlan
	if err := json.Unmarshal(b, &got); err != nil || got.Validate(got.HostID) != nil {
		t.Fatalf("source-free v2 JSON did not round-trip: plan=%+v err=%v", got, err)
	}
}

func TestReserveAttemptIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first := validMJ1Attempt()
	if err := ReserveAttempt(dir, first); err != nil {
		t.Fatalf("reserve first attempt: %v", err)
	}
	second := validMJ1Attempt()
	second.Plan.AttemptID = strings.Repeat("d", 32)
	if err := ReserveAttempt(dir, second); err == nil {
		t.Fatal("second reservation replaced an existing mutation marker")
	}
	got, err := LoadAttempt(dir)
	if err != nil || got == nil || got.Plan.AttemptID != first.Plan.AttemptID {
		t.Fatalf("original reservation not preserved: attempt=%+v err=%v", got, err)
	}
}

func TestLoadAttemptRejectsCorruptUnknownOversizedAndTrailingJSON(t *testing.T) {
	valid, err := json.Marshal(validMJ1Attempt())
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(valid), "}") + `,"unexpected":true}`
	oversized := append(append([]byte(nil), valid...),
		[]byte(strings.Repeat(" ", 16385-len(valid)))...)
	cases := map[string][]byte{
		"corrupt":       []byte(`{"version":`),
		"unknown field": []byte(unknown),
		"oversized":     oversized,
		"trailing JSON": append(append([]byte(nil), valid...), []byte(` {}`)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(AttemptPath(dir), data, 0600); err != nil {
				t.Fatal(err)
			}
			if attempt, err := LoadAttempt(dir); err == nil || attempt != nil {
				t.Fatalf("LoadAttempt accepted invalid marker: attempt=%+v err=%v", attempt, err)
			}
		})
	}
}

func TestLoadAttemptPreservesLegacyUnknownAndAcceptsV2(t *testing.T) {
	t.Run("legacy v1 unknown retains source", func(t *testing.T) {
		a := validMJ1Attempt()
		a.Phase = "unknown"
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadAttempt(dir)
		if err != nil || got == nil || got.Phase != "unknown" || got.Plan.Source.GUID != a.Plan.Source.GUID {
			t.Fatalf("legacy unknown marker not preserved: attempt=%+v err=%v", got, err)
		}
	})
	t.Run("current server v1 plan version", func(t *testing.T) {
		a := validMJ1Attempt()
		a.Plan.Version = 1
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := LoadAttempt(dir); err != nil || got == nil || got.Plan.Version != 1 {
			t.Fatalf("current v1 marker not accepted: attempt=%+v err=%v", got, err)
		}
	})
	t.Run("v2 unknown source-free marker", func(t *testing.T) {
		p := validV2Plan("rename", "rename")
		p.Source = RejoinObject{}
		a := &Attempt{Version: 2, Fingerprint: strings.Repeat("c", 64), Plan: p, Phase: "unknown"}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadAttempt(dir)
		if err != nil || got == nil || got.Version != 2 || got.Phase != "unknown" {
			t.Fatalf("v2 unknown marker not preserved: attempt=%+v err=%v", got, err)
		}
	})
	t.Run("outer and plan versions must agree", func(t *testing.T) {
		p := validV2Plan("rename", "rename")
		a := &Attempt{Version: 1, Fingerprint: strings.Repeat("c", 64), Plan: p, Phase: "unknown"}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := LoadAttempt(dir); err == nil || got != nil {
			t.Fatalf("mismatched marker versions accepted: attempt=%+v", got)
		}
	})
	t.Run("unknown marker version", func(t *testing.T) {
		a := validMJ1Attempt()
		a.Version = 3
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(AttemptPath(dir), b, 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := LoadAttempt(dir); err == nil || got != nil {
			t.Fatalf("unknown marker version accepted: attempt=%+v", got)
		}
	})
}

func TestNewBootRequiresServiceAndOSBootIdentityToChange(t *testing.T) {
	before := BootObservation{Marker: "marker-a", Started: "boot-time-a"}
	cases := []struct {
		name  string
		after BootObservation
		want  bool
	}{
		{"service restart only", BootObservation{Marker: "marker-a", Started: "boot-time-a"}, false},
		{"marker changes without OS boot", BootObservation{Marker: "marker-b", Started: "boot-time-a"}, false},
		{"OS boot changes without marker", BootObservation{Marker: "marker-a", Started: "boot-time-b"}, false},
		{"both boot identities change", BootObservation{Marker: "marker-b", Started: "boot-time-b"}, true},
		{"missing boot identity", BootObservation{Marker: "marker-b"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewBoot(before, tt.after); got != tt.want {
				t.Fatalf("NewBoot(%+v, %+v) = %t, want %t", before, tt.after, got, tt.want)
			}
		})
	}
}
