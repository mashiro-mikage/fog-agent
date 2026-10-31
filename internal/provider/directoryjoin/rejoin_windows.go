//go:build windows

package directoryjoin

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func replaceAttempt(from, to string) error {
	f, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	t, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func SetRejoinName(name string) error {
	if !rejoinName.MatchString(name) || len(name) > 15 {
		return errors.New("invalid directory rejoin name")
	}
	return withDirectoryMutation(func() error {
		n, e := syscall.UTF16PtrFromString(name)
		if e != nil {
			return e
		}
		r, _, _ := procSetComputerNameEx.Call(computerNamePhysicalDnsHostname, uintptr(unsafe.Pointer(n)))
		if r == 0 {
			return errors.New("setting directory rejoin name failed")
		}
		return nil
	})
}

func Rebind(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if plan.Version != 2 || plan.Operation != "rebind" {
		return 0, errors.New("legacy directory plans cannot execute a rebind")
	}
	if err := plan.Validate(plan.HostID); err != nil {
		return 0, err
	}
	if p.Username == "" || p.Password.Empty() {
		return 0, errors.New("directory rejoin credential missing")
	}
	var code uint32
	err := withDirectoryMutation(func() error {
		var callErr error
		code, callErr = rebindWindowsLocked(ctx, p, plan)
		return callErr
	})
	return code, err
}

func rebindWindowsLocked(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// WITH_NEW_NAME consumes Windows' pending name. Recheck it under the same
	// lock as the native call, after any competing legacy Join/Rename ended.
	pending, err := pendingComputerName()
	if err != nil || !strings.EqualFold(pending, plan.Name) {
		return 0, errors.New("directory rejoin pending name changed before dispatch")
	}
	if plan.Version == 2 {
		current, e := os.Hostname()
		if e != nil || !strings.EqualFold(current, plan.ExpectedCurrent) {
			return 0, errors.New("directory operation current name changed before dispatch")
		}
	}
	dnsDomain, err := observeDNSDomain()
	role := observeMachineRole()
	if err != nil || !strings.EqualFold(dnsDomain, plan.Domain) || (role != "workstation" && role != "member_server") {
		return 0, errors.New("directory rejoin domain or role changed before dispatch")
	}
	domain, err := syscall.UTF16PtrFromString(plan.Domain + `\` + plan.DC)
	if err != nil {
		return 0, err
	}
	user, err := syscall.UTF16PtrFromString(p.Username)
	if err != nil {
		return 0, errors.New("invalid directory rejoin account")
	}
	password, err := syscall.UTF16FromString(p.Password.Reveal())
	if err != nil {
		return 0, errors.New("invalid directory rejoin credential")
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	var ou *uint16
	flags := uintptr(0x421)
	if plan.Mode == "create" {
		flags = 0x20423
		if p.OU != "" {
			ou, err = syscall.UTF16PtrFromString(p.OU)
			if err != nil {
				return 0, errors.New("invalid directory rejoin OU")
			}
		}
	}
	// No unjoin/rename/delete/fallback. NetJoinDomain is synchronous and not cancelled by ctx.
	r, _, _ := procNetJoinDomain.Call(0, uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(ou)), uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(&password[0])), flags)
	return uint32(r), nil
}

// RenameForPlan reuses the native rename implementation under the same mutex.
func RenameForPlan(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if ValidateRenamePlan(plan) != nil {
		return 0, errors.New("invalid directory rename plan")
	}
	var code uint32
	err := withDirectoryMutation(func() error {
		var callErr error
		code, callErr = renameForPlanWindowsLocked(ctx, p, plan)
		return callErr
	})
	return code, err
}

func renameForPlanWindowsLocked(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	o, err := ObserveRejoin(plan.DC)
	if err != nil || validateRenameObservation(plan, o) != nil {
		return 0, errors.New("directory rename observation changed before dispatch")
	}
	p.RenameTo = plan.Name
	return renamePlanResult(renameWindowsLocked(ctx, p))
}
