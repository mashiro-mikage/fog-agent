package directoryjoin

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// RejoinObject is public directory metadata, never a credential.
type RejoinObject struct {
	GUID            string   `json:"guid"`
	SID             string   `json:"sid"`
	DN              string   `json:"dn"`
	Account         string   `json:"account"`
	DNS             string   `json:"dns"`
	UAC             uint32   `json:"uac"`
	PasswordLastSet string   `json:"pwd_last_set"`
	SPNs            []string `json:"spns"`
}

type RejoinPlan struct {
	TaskID          int           `json:"task_id"`
	Version         int           `json:"version,omitempty"`
	Operation       string        `json:"operation,omitempty"`
	ExpectedCurrent string        `json:"expected_current,omitempty"`
	ExpectedPending string        `json:"expected_pending,omitempty"`
	RetryAuthorized bool          `json:"retry_authorized,omitempty"`
	AttemptID       string        `json:"attempt_id"`
	HostID          int           `json:"host_id"`
	ConfigRevision  string        `json:"config_revision"`
	Phase           string        `json:"phase"`
	Name            string        `json:"name"`
	Domain          string        `json:"domain"`
	Mode            string        `json:"mode"`
	DC              string        `json:"dc"`
	Source          RejoinObject  `json:"source,omitempty"`
	Target          *RejoinObject `json:"target"`
	Reason          string        `json:"reason,omitempty"`
}

// MarshalJSON preserves the v1 source object for legacy plans while keeping
// source metadata out of v2 plans, even when Source is its zero value.
func (p RejoinPlan) MarshalJSON() ([]byte, error) {
	type plain RejoinPlan
	b, err := json.Marshal(plain(p))
	if err != nil || p.Version != 2 {
		return b, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	delete(fields, "source")
	return json.Marshal(fields)
}

var rejoinGUID = regexp.MustCompile(`(?i)^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$`)
var rejoinName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$`)
var fogHostname = regexp.MustCompile(`^[a-zA-Z0-9_!@#$%^()\-'{}.~]{1,15}$`)
var rejoinID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (p RejoinPlan) Validate(hostID int) error {
	validName := rejoinName.MatchString(p.Name)
	if p.Version == 2 && (p.Operation == "rename" || p.Operation == "join") {
		validName = fogHostname.MatchString(p.Name)
	}
	if p.HostID != hostID || hostID < 1 || !rejoinID.MatchString(p.AttemptID) || !rejoinID.MatchString(p.ConfigRevision) ||
		!validName || len(p.Name) > 15 || (p.Operation != "join" && !validDCFQDN(p.Domain)) || (p.Operation == "join" && !validJoinDomain(p.Domain)) || !validDCFQDN(p.DC) || p.TaskID < 0 {
		return errors.New("invalid directory rejoin plan")
	}
	if p.Version == 2 {
		return p.validateV2()
	}
	if p.Version != 0 && p.Version != 1 || !rejoinGUID.MatchString(p.Source.GUID) || p.Source.SID == "" {
		return errors.New("invalid directory rejoin plan")
	}
	if p.Mode == "existing" {
		if p.Target == nil || !rejoinGUID.MatchString(p.Target.GUID) || p.Target.SID == "" || p.Source.SID == p.Target.SID || strings.EqualFold(p.Source.GUID, p.Target.GUID) || !strings.EqualFold(p.Target.Account, p.Name+"$") {
			return errors.New("unconfirmed directory rejoin target")
		}
	} else if p.Mode != "create" || (p.Target != nil && (p.Phase == "ready" || !rejoinGUID.MatchString(p.Target.GUID) || p.Target.SID == "" || strings.EqualFold(p.Target.GUID, p.Source.GUID) || !strings.EqualFold(p.Target.Account, p.Name+"$"))) || strings.EqualFold(strings.TrimSuffix(p.Source.Account, "$"), p.Name) {
		return errors.New("invalid directory rejoin mode")
	}
	return nil
}

func (p RejoinPlan) validateV2() error {
	if !validNetBIOSName(p.ExpectedCurrent) || !validNetBIOSName(p.ExpectedPending) ||
		(!strings.EqualFold(p.ExpectedPending, p.ExpectedCurrent) && !strings.EqualFold(p.ExpectedPending, p.Name)) {
		return errors.New("invalid directory operation expected names")
	}
	switch p.Operation {
	case "join":
		if p.Mode != "join" || p.TaskID <= 0 || p.Target != nil {
			return errors.New("invalid task join plan")
		}
	case "rebind":
		if p.Mode != "existing" && p.Mode != "create" {
			return errors.New("invalid directory rejoin operation")
		}
		if p.Mode == "existing" {
			if !validTarget(p.Target, p.Name) {
				return errors.New("unconfirmed directory rejoin target")
			}
		} else if p.Phase == "ready" {
			if p.Target != nil {
				return errors.New("invalid directory rejoin create target")
			}
		} else if p.Target == nil || !validTarget(p.Target, p.Name) {
			return errors.New("invalid directory rejoin create target")
		}
	case "rename":
		if p.Mode != "rename" || !validNetBIOSName(p.ExpectedCurrent) || !validNetBIOSName(p.ExpectedPending) ||
			(!strings.EqualFold(p.ExpectedPending, p.ExpectedCurrent) && !strings.EqualFold(p.ExpectedPending, p.Name)) {
			return errors.New("invalid directory rename plan")
		}
		if p.Target != nil && !validTarget(p.Target, p.Name) && !validTarget(p.Target, p.ExpectedCurrent) {
			return errors.New("invalid directory rename target")
		}
	default:
		return errors.New("invalid directory rejoin operation")
	}
	return nil
}

func validNetBIOSName(name string) bool {
	if len(name) == 0 || len(name) > 15 || !fogHostname.MatchString(name) {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false
}

func validTarget(target *RejoinObject, name string) bool {
	return target != nil && rejoinGUID.MatchString(target.GUID) && target.SID != "" &&
		strings.EqualFold(target.Account, name+"$")
}

// Attempt is a single mutation latch, not an event journal. Unknown never replays.
type Attempt struct {
	Version         int             `json:"version"`
	Fingerprint     string          `json:"fingerprint"`
	Plan            RejoinPlan      `json:"plan"`
	Phase           string          `json:"phase"`
	BeforeBoot      BootObservation `json:"before_boot"`
	NativeStatus    *uint32         `json:"native_status,omitempty"`
	RebootRequested bool            `json:"reboot_requested"`
}

func AttemptPath(dir string) string { return filepath.Join(dir, "directory-rejoin-attempt.json") }

func LoadAttempt(dir string) (*Attempt, error) {
	f, err := os.Open(AttemptPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 16384 {
		return nil, errors.New("invalid directory rejoin marker size")
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	var a Attempt
	if err = d.Decode(&a); err != nil {
		return nil, errors.New("invalid directory rejoin marker")
	}
	var tail any
	if d.Decode(&tail) != io.EOF || len(a.Fingerprint) != 64 || a.Plan.Validate(a.Plan.HostID) != nil {
		return nil, errors.New("invalid directory rejoin marker")
	}
	switch a.Version {
	case 1:
		// The current server includes version: 1 in its plan. Older markers
		// were written by an agent DTO that ignored that field, so both forms
		// are legacy v1 and retain the strict Source requirements.
		if a.Plan.Version != 0 && a.Plan.Version != 1 {
			return nil, errors.New("invalid directory rejoin marker version")
		}
	case 2:
		if a.Plan.Version != 2 {
			return nil, errors.New("invalid directory rejoin marker version")
		}
	default:
		return nil, errors.New("invalid directory rejoin marker version")
	}
	switch a.Phase {
	case "reserved", "may_have_run", "awaiting_reboot", "verified", "failed", "unknown":
	default:
		return nil, errors.New("invalid directory rejoin marker phase")
	}
	return &a, nil
}

func writeAttemptFile(path string, a *Attempt) error {
	b, err := json.Marshal(a)
	if err != nil || len(b) > 16384 {
		return errors.New("directory rejoin marker too large")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func ReserveAttempt(dir string, a *Attempt) error {
	return withAttemptLock(dir, func() error {
		if err := writeAttemptFile(AttemptPath(dir), a); err != nil {
			return err
		}
		return syncAttemptDir(dir)
	})
}
func SaveAttempt(dir string, a *Attempt) error {
	return withAttemptLock(dir, func() error {
		current, err := LoadAttempt(dir)
		if err != nil {
			return err
		}
		if current == nil || current.Fingerprint != a.Fingerprint || !reflect.DeepEqual(current.Plan, a.Plan) {
			return errors.New("directory marker binding changed; update refused")
		}
		if !attemptPhaseUpdate(current.Phase, a.Phase) {
			return errors.New("directory marker phase would regress; update refused")
		}
		if current.RebootRequested != a.RebootRequested {
			return errors.New("directory reboot latch changed; conditional update required")
		}
		if current.Phase == a.Phase && !reflect.DeepEqual(current, a) {
			return errors.New("directory marker snapshot changed; update refused")
		}
		return saveAttemptLocked(dir, a)
	})
}

func saveAttemptLocked(dir string, a *Attempt) error {
	path := AttemptPath(dir)
	tmp := path + ".tmp"
	if err := writeAttemptFile(tmp, a); err != nil {
		return err
	}
	if err := replaceAttempt(tmp, path); err != nil {
		return err
	}
	return syncAttemptDir(dir)
}

// SetAttemptRebootRequested changes only the reboot latch and only when the
// complete marker still matches the caller's snapshot. Concurrent
// coordinators therefore cannot both acquire a request from the same
// awaiting_reboot marker.
func SetAttemptRebootRequested(dir string, expected *Attempt, requested bool) error {
	return withAttemptLock(dir, func() error {
		current, err := LoadAttempt(dir)
		if err != nil {
			return err
		}
		if expected == nil || current == nil || !reflect.DeepEqual(current, expected) {
			return errors.New("directory reboot marker changed; update refused")
		}
		if current.Phase != "awaiting_reboot" || current.RebootRequested == requested {
			return errors.New("directory reboot request transition refused")
		}
		next := *current
		next.RebootRequested = requested
		return saveAttemptLocked(dir, &next)
	})
}

func attemptPhaseUpdate(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "reserved":
		return to == "may_have_run" || to == "unknown"
	case "may_have_run":
		return to == "awaiting_reboot" || to == "failed" || to == "unknown"
	case "awaiting_reboot":
		return to == "verified" || to == "unknown"
	default:
		return false
	}
}

func NewBoot(before, after BootObservation) bool {
	return before.Marker != "" && before.Started != "" && after.Marker != "" && after.Started != "" && before.Marker != after.Marker && before.Started != after.Started
}

// Join accepts a DNS domain or the established flat-domain policy, not shell text.
func validJoinDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.TrimSpace(domain) != domain {
		return false
	}
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
