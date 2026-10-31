package directoryjoin

import "testing"

func renameObservationPlan() RejoinPlan {
	plan := validV2Plan("rename", "rename")
	plan.Target = &RejoinObject{
		GUID:    "22222222-2222-2222-2222-222222222222",
		SID:     "S-1-5-21-2",
		Account: plan.ExpectedCurrent + "$",
	}
	return plan
}

func renameObservation(plan RejoinPlan, secureChannel string) RejoinObservation {
	return RejoinObservation{
		CurrentName: plan.ExpectedCurrent, PendingName: plan.ExpectedPending,
		Domain: plan.Domain, Role: "workstation", SecureChannel: secureChannel,
	}
}

func TestValidateRenameObservationAllowsKnownFalseButRejectsUnknown(t *testing.T) {
	plan := renameObservationPlan()
	for _, secureChannel := range []string{"true", "false"} {
		t.Run(secureChannel, func(t *testing.T) {
			if err := validateRenameObservation(plan, renameObservation(plan, secureChannel)); err != nil {
				t.Fatalf("known secure channel %q rejected: %v", secureChannel, err)
			}
		})
	}
	if err := validateRenameObservation(plan, renameObservation(plan, "unknown")); err == nil {
		t.Fatal("unknown secure channel accepted for native rename")
	}
}

func TestValidateRenameObservationKeepsIdentityAndMembershipGuards(t *testing.T) {
	plan := renameObservationPlan()
	cases := map[string]func(*RejoinObservation){
		"current name": func(o *RejoinObservation) { o.CurrentName = "OTHER" },
		"pending name": func(o *RejoinObservation) { o.PendingName = "OTHER" },
		"domain":       func(o *RejoinObservation) { o.Domain = "other.example.com" },
		"role":         func(o *RejoinObservation) { o.Role = "domain_controller" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := renameObservation(plan, "false")
			mutate(&o)
			if err := validateRenameObservation(plan, o); err == nil {
				t.Fatalf("changed %s accepted", name)
			}
		})
	}
}

func TestValidateRenamePlanRequiresPinnedOldIdentityButReadsLegacyShape(t *testing.T) {
	legacy := renameObservationPlan()
	legacy.Target = nil
	legacy.Phase = "verified"
	if err := legacy.Validate(legacy.HostID); err != nil {
		t.Fatalf("legacy completed-plan shape must remain readable: %v", err)
	}
	if err := ValidateRenamePlan(legacy); err == nil {
		t.Fatal("new rename dispatch accepted a plan without the old account identity")
	}

	wrongAccount := renameObservationPlan()
	wrongAccount.Target.Account = wrongAccount.Name + "$"
	if err := wrongAccount.Validate(wrongAccount.HostID); err != nil {
		t.Fatalf("compatible target account shape rejected by plan decoder: %v", err)
	}
	if err := ValidateRenamePlan(wrongAccount); err == nil {
		t.Fatal("rename dispatch accepted a target not bound to ExpectedCurrent")
	}

	if err := ValidateRenamePlan(renameObservationPlan()); err != nil {
		t.Fatalf("valid old-account pin rejected: %v", err)
	}
}

func TestRenamePlanResultPreservesNativeFailureAndStopsOnPartialLocalFailure(t *testing.T) {
	if code, err := renamePlanResult(Result{Status: StatusFailed, NativeStatus: 5}); code != 5 || err != nil {
		t.Fatalf("native failure result = (%d, %v), want (5, nil)", code, err)
	}
	if code, err := renamePlanResult(Result{Status: StatusFailed}); code != 0 || err == nil {
		t.Fatalf("partial local failure result = (%d, %v), want (0, error)", code, err)
	}
	if code, err := renamePlanResult(Result{Status: StatusRenamed}); code != 0 || err != nil {
		t.Fatalf("successful rename result = (%d, %v), want (0, nil)", code, err)
	}
}
