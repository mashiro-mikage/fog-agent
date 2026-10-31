package directoryjoin

import (
	"errors"
	"net"
	"strings"
)

// BootObservation identifies the current OS boot independently of service
// lifetime. Marker is backed by a volatile machine registry key on Windows;
// Started is the OS-reported LastBootUpTime.
type BootObservation struct {
	Marker  string `json:"marker"`
	Started string `json:"started"`
}

// RejoinObservation is the read-only local state needed before a directory
// rejoin decision. Names are flattened to match the planned server wire shape.
type RejoinObservation struct {
	CurrentName   string          `json:"current_name"`
	PendingName   string          `json:"pending_name"`
	Domain        string          `json:"domain"`
	Netbios       string          `json:"netbios"`
	Role          string          `json:"role"`
	SecureChannel string          `json:"secure_channel"`
	Boot          BootObservation `json:"boot"`
}

var errObservationUnsupported = errors.New("directory rejoin observation is unsupported on this platform")

// ValidateRenamePlan applies the current dispatch contract without invalidating
// completed legacy markers that did not pin a directory object.
func ValidateRenamePlan(plan RejoinPlan) error {
	if plan.Version != 2 || plan.Operation != "rename" || plan.Validate(plan.HostID) != nil ||
		!validTarget(plan.Target, plan.ExpectedCurrent) {
		return errors.New("directory rename requires the existing account identity")
	}
	return nil
}

func validateRenameObservation(plan RejoinPlan, o RejoinObservation) error {
	if ValidateRenamePlan(plan) != nil || !strings.EqualFold(o.CurrentName, plan.ExpectedCurrent) ||
		!strings.EqualFold(o.PendingName, plan.ExpectedPending) || !strings.EqualFold(o.Domain, plan.Domain) ||
		(o.Role != "workstation" && o.Role != "member_server") ||
		(o.SecureChannel != "true" && o.SecureChannel != "false") {
		return errors.New("directory rename observation changed before dispatch")
	}
	return nil
}

func renamePlanResult(result Result) (uint32, error) {
	if result.NativeStatus != 0 {
		return result.NativeStatus, nil
	}
	if result.Status != StatusRenamed {
		return 0, errors.New("directory rename result requires review")
	}
	return 0, nil
}

// validDCFQDN accepts an ASCII DNS FQDN and rejects values that could be
// interpreted as a command fragment, IP literal, or partial hostname.
func validDCFQDN(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
