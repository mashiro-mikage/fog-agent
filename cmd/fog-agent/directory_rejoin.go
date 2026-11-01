package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/provider"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
	"github.com/FOGProject/fog-agent/internal/reboot"
)

var observeRejoin = directoryjoin.ObserveRejoin
var rebindDirectory = directoryjoin.Rebind
var joinDirectory = directoryjoin.JoinForPlan
var setRejoinName = directoryjoin.SetRejoinName
var renameDirectory = func(ctx context.Context, policy directoryjoin.Policy, plan directoryjoin.RejoinPlan) (uint32, error) {
	return directoryjoin.RenameForPlan(ctx, policy, plan)
}

// A failed network gate must never prevent a due local update rollback.
// Keep this boundary independent of GOOS so its ordering is testable offline.
func prepareWindowsRun(ctx context.Context, st *enroll.State, c *enroll.Client, out *sayer) error {
	return beforeDirectoryNetwork(func() bool { return checkProbation(st, out) }, func() error {
		return prepareDirectoryIdentity(ctx, st, c)
	})
}

func beforeDirectoryNetwork(rollback func() bool, prepare func() error) error {
	if rollback() {
		return errUpdated
	}
	return prepare()
}

// Nothing cached may act until this process has checked its live identity.
func prepareDirectoryIdentity(ctx context.Context, st *enroll.State, c *enroll.Client) error {
	if err := c.RequireDirectoryFeatures(ctx); err != nil {
		return err
	}
	live := readIdentity()
	if len(st.Cert) > 0 {
		if err := c.UseCertificate(st.Cert, st.Key); err != nil {
			return err
		}
		a, err := c.CheckIdentity(ctx, live)
		if err != nil {
			return err
		}
		if a.Identity.Status == "mismatch" {
			return st.RotateIdentity(live)
		}
		if st.Config.HostID != 0 && st.Config.HostID != a.Identity.HostID {
			return errors.New("certificate and saved host do not agree")
		}
		st.Config.HostID = a.Identity.HostID
		if err = st.RememberIdentity(live); err != nil {
			return err
		}
		return st.SaveConfig()
	}
	// Certificate loss is not permission to enroll a copied key on another
	// physical host. Settle even an existing key against its local identity.
	trust := st.Config.SystemTrust
	if _, err := st.EnsureKey(live); err != nil {
		return err
	}
	st.Config.SystemTrust = trust
	return st.SaveConfig()
}

func attachDirectoryContext(st *enroll.State, r *enroll.PollRequest) {
	if runtime.GOOS != "windows" {
		return
	}
	live := readIdentity()
	r.Features = []string{enroll.DirectoryJoinTargetFeature, enroll.DirectoryTaskOperationsFeature}
	r.DirectoryObservation = st.DirectoryObservation
	r.Identity = &live
	r.DirectoryAttempt = localDirectoryAttempt(st.Dir)
}

func localDirectoryAttempt(dir string) *enroll.DirectoryAttempt {
	summary := &enroll.DirectoryAttempt{Phase: "none"}
	marker, err := directoryjoin.LoadAttempt(dir)
	if err != nil {
		summary.Phase = "unreadable"
	} else if marker != nil {
		summary = &enroll.DirectoryAttempt{Phase: marker.Phase,
			AttemptID: marker.Plan.AttemptID, HostID: marker.Plan.HostID, Fingerprint: marker.Fingerprint}
	}
	return summary
}

func rejoinReport(ctx context.Context, st *enroll.State, c *enroll.Client, a *directoryjoin.Attempt, phase string, o directoryjoin.RejoinObservation, boot bool) error {
	secure := "unknown"
	if o.SecureChannel == "true" {
		secure = "healthy"
	}
	if o.SecureChannel == "false" {
		secure = "broken"
	}
	_, err := c.Result(ctx, enroll.ResultRequest{Revision: st.Config.AppliedRevision, Capability: "directory", Status: provider.StatusApplied,
		Item: &enroll.ResultItem{ID: st.Config.HostID, AttemptID: a.Plan.AttemptID, ConfigRevision: a.Plan.ConfigRevision, TaskID: a.Plan.TaskID, Status: phase, NativeStatus: a.NativeStatus, SecureChannel: secure, BootChanged: boot, CurrentName: o.CurrentName, Domain: o.Domain, Netbios: o.Netbios}})
	return err
}

func processRejoin(ctx context.Context, st *enroll.State, c *enroll.Client, p *directoryjoin.RejoinPlan, out *sayer) error {
	a, err := directoryjoin.LoadAttempt(st.Dir)
	if err != nil {
		return err
	}
	if a != nil && a.Version != 2 && a.Phase != "verified" {
		return errors.New("legacy directory operation requires review; automatic execution stopped")
	}
	// A successful, older identity's operation is history, not authority for
	// this key. This also handles hosts already re-enrolled before this fix,
	// without requiring another identity reset. Never retire uncertainty.
	if a != nil && a.Phase == "verified" {
		fp, e := st.KeyFingerprint()
		if e != nil {
			return e
		}
		if a.Fingerprint != fp || a.Plan.HostID != st.Config.HostID {
			if e = directoryjoin.ArchiveVerifiedAttempt(st.Dir, a); e != nil {
				return e
			}
			a = nil
		}
	}
	if p == nil {
		if a != nil && a.Phase != "verified" {
			return errors.New("directory rejoin requires server confirmation")
		}
		return nil
	}
	if p.Phase == "blocked" {
		out.say("directory rejoin: blocked (" + p.Reason + ")")
		return nil
	}
	if p.Version != 2 {
		return errors.New("legacy directory plans cannot start a new operation")
	}
	if p.Validate(st.Config.HostID) != nil {
		return errors.New("directory rejoin plan invalid")
	}
	if p.Operation == "rename" && p.Phase == "ready" {
		if err := directoryjoin.ValidateRenamePlan(*p); err != nil {
			return err
		}
	}
	fp, err := st.KeyFingerprint()
	if err != nil {
		return err
	}
	if a != nil && a.Plan.AttemptID != p.AttemptID {
		if p.Phase != "ready" || a.Plan.HostID != st.Config.HostID {
			return errors.New("previous directory rejoin unresolved")
		}
		if a.Phase == "verified" {
			err = directoryjoin.ArchiveVerifiedAttempt(st.Dir, a)
		} else {
			if err = directoryjoin.ValidateReservedRetry(a, *p, st.Config.HostID, fp); err != nil {
				return err
			}
			err = directoryjoin.RemoveAttemptForRetry(st.Dir, a, *p, st.Config.HostID, fp)
		}
		if err != nil {
			return err
		}
		a = nil
	}
	if a == nil {
		if p.Phase != "ready" {
			return errors.New("directory rejoin marker absent; automatic retry refused")
		}
		o, err := observeRejoin(p.DC)
		if err != nil {
			return err
		}
		if o.Role != "workstation" && o.Role != "member_server" && !(p.Operation == "join" && o.Role == "standalone_server") {
			return errors.New("directory rejoin does not support this machine role")
		}
		if (p.Operation == "join" && o.Domain != "") || (p.Operation != "join" && !strings.EqualFold(o.Domain, p.Domain)) {
			return errors.New("directory rejoin domain mismatch")
		}
		if !strings.EqualFold(o.CurrentName, p.ExpectedCurrent) || !strings.EqualFold(o.PendingName, p.ExpectedPending) {
			return errors.New("directory operation names changed before reservation")
		}
		if p.Operation != "rename" && !strings.EqualFold(o.PendingName, p.Name) {
			if !strings.EqualFold(o.PendingName, o.CurrentName) {
				return errors.New("directory rejoin conflicts with another pending rename")
			}
		}
		a = &directoryjoin.Attempt{Version: 2, Fingerprint: fp, Plan: *p, Phase: "reserved", BeforeBoot: o.Boot}
		if err = directoryjoin.ReserveAttempt(st.Dir, a); err != nil {
			return err
		}
		policy, err := c.StartRejoin(ctx, *p)
		if err != nil {
			a.Phase = "unknown"
			_ = directoryjoin.SaveAttempt(st.Dir, a)
			return err
		}
		defer policy.Password.Zero()
		a.Phase = "may_have_run"
		if err = directoryjoin.SaveAttempt(st.Dir, a); err != nil {
			return err
		}
		// A pending-name update is already an OS mutation. Reserve and claim
		// first, then persist the uncertainty latch before either native call.
		if p.Operation != "rename" && !strings.EqualFold(o.PendingName, p.Name) {
			if err = setRejoinName(p.Name); err == nil {
				o, err = observeRejoin(p.DC)
				if err == nil && !strings.EqualFold(o.PendingName, p.Name) {
					err = errors.New("directory rejoin pending name mismatch")
				}
			}
			if err != nil {
				a.Phase = "unknown"
				if e := directoryjoin.SaveAttempt(st.Dir, a); e != nil {
					return e
				}
				_ = rejoinReport(ctx, st, c, a, "unknown", o, false)
				return errors.New("directory name mutation outcome requires review; automatic replay stopped")
			}
		}
		var code uint32
		var callErr error
		if p.Operation == "rename" {
			code, callErr = renameDirectory(ctx, *policy, *p)
		} else if p.Operation == "join" {
			code, callErr = joinDirectory(ctx, *policy, *p)
		} else {
			code, callErr = rebindDirectory(ctx, *policy, *p)
		}
		if callErr != nil {
			a.Phase = "unknown"
			if e := directoryjoin.SaveAttempt(st.Dir, a); e != nil {
				return e
			}
			_ = rejoinReport(ctx, st, c, a, "unknown", o, false)
			return errors.New("directory rejoin outcome unknown; manual review required")
		}
		a.NativeStatus = &code
		if code != 0 {
			a.Phase = "failed"
			out.say(fmt.Sprintf("directory rejoin: failed (native 0x%08x)", code))
			if err = directoryjoin.SaveAttempt(st.Dir, a); err != nil {
				return err
			}
			return rejoinReport(ctx, st, c, a, "failed", o, false)
		}
		a.Phase = "awaiting_reboot"
		out.say("directory rejoin: native success; Windows restart and verification pending")
		if err = directoryjoin.SaveAttempt(st.Dir, a); err != nil {
			return err
		}
		st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{Source: "directory-rejoin", Detail: "directory rejoin needs a Windows restart", Force: policy.Reboot, Mode: reboot.ModeReboot})
		st.Config.FactsChecked = time.Time{}
		if err = st.SaveConfig(); err != nil {
			return err
		}
	}
	if a.Fingerprint != fp || a.Plan.HostID != st.Config.HostID {
		return errors.New("directory rejoin marker belongs to another identity")
	}
	switch a.Phase {
	case "reserved", "may_have_run", "unknown":
		_ = rejoinReport(ctx, st, c, a, "unknown", directoryjoin.RejoinObservation{}, false)
		return errors.New("directory rejoin outcome unknown; automatic replay stopped")
	case "failed":
		return rejoinReport(ctx, st, c, a, "failed", directoryjoin.RejoinObservation{}, false)
	case "verified":
		return st.SaveConfig()
	case "awaiting_reboot":
		o, err := observeRejoin(a.Plan.DC)
		if err != nil {
			return err
		}
		// Recover a lost pending-result acknowledgement before confirming the boot.
		if p.Phase != "verified" {
			if err = rejoinReport(ctx, st, c, a, "awaiting_reboot", o, false); err != nil {
				return err
			}
		}
		if directoryjoin.NewBoot(a.BeforeBoot, o.Boot) {
			if o.SecureChannel != "true" || !strings.EqualFold(o.CurrentName, a.Plan.Name) || !strings.EqualFold(o.PendingName, a.Plan.Name) || (!strings.EqualFold(o.Domain, a.Plan.Domain) && !strings.EqualFold(o.Netbios, a.Plan.Domain)) || (o.Role != "workstation" && o.Role != "member_server") {
				return errors.New("directory rejoin verification not healthy; read-only recheck pending")
			}
			if err = rejoinReport(ctx, st, c, a, "verified", o, true); err != nil {
				return err
			}
			a.Phase = "verified"
			out.say("directory rejoin: verified after Windows restart")
			if err = directoryjoin.SaveAttempt(st.Dir, a); err != nil {
				return err
			}
			st.Config.FactsChecked = time.Time{}
			st.Config.PendingReboot = reboot.Drop(st.Config.PendingReboot, "directory-rejoin")
			return st.SaveConfig()
		}
		if !a.RebootRequested && len(st.Config.PendingReboot) == 0 {
			return errors.New("directory rejoin restart not recorded; manual restart required")
		}
	}
	return nil
}
