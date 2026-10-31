//go:build windows

package directoryjoin

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// Windows joins through netapi32's NetJoinDomain.
//
// The direct call and NOT `Add-Computer` or `netdom`, and the reason is the
// credential rather than convenience. A command line is visible to every
// process on the machine through the process table, and a PowerShell script
// -- even one fed on stdin -- is captured verbatim by script block logging
// where an estate has it on, which is a place a domain join password must
// never be. NetJoinDomain takes the password as a UTF-16 pointer in this
// process's own memory: no argv, no script text, nothing on disk.
type Windows struct{}

var (
	netapi32                     = syscall.NewLazyDLL("netapi32.dll")
	procNetJoinDomain            = netapi32.NewProc("NetJoinDomain")
	procNetRenameMachineInDomain = netapi32.NewProc("NetRenameMachineInDomain")
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procSetComputerNameEx        = kernel32.NewProc("SetComputerNameExW")
)

// computerNamePhysicalDnsHostname is the COMPUTER_NAME_FORMAT that sets the
// DNS host name and, with it, the NetBIOS name, for the next boot.
const computerNamePhysicalDnsHostname = 5

// NetJoinDomain options.
const (
	// NETSETUP_JOIN_DOMAIN: join a domain rather than a workgroup.
	netsetupJoinDomain = 0x00000001
	// NETSETUP_ACCT_CREATE: create the computer account. When the join
	// cannot use one already there by that name (a reimaged machine), it
	// fails with NERR_UserExists, and joinOrReuse retries without this
	// flag to reuse it.
	netsetupAcctCreate = 0x00000002
	// NETSETUP_JOIN_WITH_NEW_NAME: join under the name the machine will
	// have after its next boot, not the one it runs under now. The
	// hostname capability runs before this one in the same poll, so a
	// machine renamed and joined together has its new name pending here.
	// Without the flag the computer object is created under the OLD name,
	// and after the reboot the machine and its object disagree (design
	// 0017 section 2). With no rename pending the two names are the same.
	// The legacy client set it on every join.
	netsetupJoinWithNewName = 0x00000400
)

// Available reports whether the join API is here. It is, on every Windows
// this agent supports.
func (Windows) Available() (bool, string) {
	if err := procNetJoinDomain.Find(); err != nil {
		return false, "netapi32!NetJoinDomain was not found; this machine cannot be joined"
	}
	return true, ""
}

// Join adds the machine to the domain, creating the computer object in the
// requested OU.
//
// The OU is passed to the join rather than fixed up afterwards. Windows
// creates the object in `CN=Computers` when it is not told otherwise, and
// then the object has to be moved -- so an estate that cares where its
// machines live gets a window, however short, where a new machine sits in
// the default container inheriting whatever policy is linked there.
func (Windows) Join(ctx context.Context, p Policy) Result {
	var result Result
	err := withDirectoryMutation(func() error {
		result = joinWindowsLocked(ctx, p)
		return nil
	})
	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()
	}
	return result
}

func joinWindowsLocked(ctx context.Context, p Policy) Result {
	domain, err := syscall.UTF16PtrFromString(p.Domain)
	if err != nil {
		return Result{Status: StatusFailed, Error: "domain is not usable: " + err.Error()}
	}
	account, err := syscall.UTF16PtrFromString(p.Username)
	if err != nil {
		return Result{Status: StatusFailed, Error: "username is not usable: " + err.Error()}
	}
	password, err := syscall.UTF16PtrFromString(p.Password.Reveal())
	if err != nil {
		// Deliberately does not echo err.Error(): UTF16PtrFromString's
		// failure message quotes the offending string, which here is the
		// password.
		return Result{Status: StatusFailed, Error: "the join password contains a NUL and cannot be used"}
	}

	// A nil lpAccountOU means the domain's default container, which is what
	// an empty OU on the host record should mean.
	var ou *uint16
	if p.OU != "" {
		ou, err = syscall.UTF16PtrFromString(p.OU)
		if err != nil {
			return Result{Status: StatusFailed, Error: "OU is not usable: " + err.Error()}
		}
	}

	status := joinOrReuse(func(create bool) uint32 {
		options, accountOU := uintptr(netsetupJoinDomain|netsetupJoinWithNewName), ou
		if create {
			options |= netsetupAcctCreate
		} else {
			// Taking over an existing object: it stays where it is, so
			// there is no container to create it in. The server's
			// placement half moves it if the OU differs.
			accountOU = nil
		}
		r, _, _ := procNetJoinDomain.Call(
			0, // lpServer: nil, let Windows locate a domain controller
			uintptr(unsafe.Pointer(domain)),
			uintptr(unsafe.Pointer(accountOU)),
			uintptr(unsafe.Pointer(account)),
			uintptr(unsafe.Pointer(password)),
			options,
		)
		return uint32(r)
	})
	if status != 0 {
		return Result{Status: StatusFailed, Error: joinError(status)}
	}
	// Windows always needs one: the machine is not actually operating as a
	// domain member until it restarts.
	return Result{Status: StatusJoined, Reboot: true}
}

// Rename renames the machine and its computer object together.
//
// NetRenameMachineInDomain with the join credential, as Rename-Computer
// -DomainCredential does and as the legacy client did. The machine cannot do
// this as itself: its own account may not rename its object (design 0017
// section 1.3, measured as access denied). NETSETUP_ACCT_CREATE is the flag
// that renames the account in the domain and not only the machine.
//
// SetComputerNameEx follows it, as it did in the legacy client, so the DNS
// host name pending for the next boot is the new name whatever the rename
// call wrote: that pending name is what the hostname capability and the
// next Decide read to know the rename is done.
func (Windows) Rename(ctx context.Context, p Policy) Result {
	var result Result
	err := withDirectoryMutation(func() error {
		result = renameWindowsLocked(ctx, p)
		return nil
	})
	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()
	}
	return result
}

func renameWindowsLocked(ctx context.Context, p Policy) Result {
	name, err := syscall.UTF16PtrFromString(p.RenameTo)
	if err != nil {
		return Result{Status: StatusFailed, Error: "new name is not usable: " + err.Error()}
	}
	account, err := syscall.UTF16PtrFromString(p.Username)
	if err != nil {
		return Result{Status: StatusFailed, Error: "username is not usable: " + err.Error()}
	}
	password, err := syscall.UTF16PtrFromString(p.Password.Reveal())
	if err != nil {
		// As in Join: the error would quote the password.
		return Result{Status: StatusFailed, Error: "the join password contains a NUL and cannot be used"}
	}
	status, _, _ := procNetRenameMachineInDomain.Call(
		0, // lpServer: nil, this machine
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(account)),
		uintptr(unsafe.Pointer(password)),
		uintptr(netsetupAcctCreate),
	)
	if status != 0 {
		return Result{Status: StatusFailed, Error: renameError(uint32(status)), NativeStatus: uint32(status)}
	}
	if r, _, e := procSetComputerNameEx.Call(computerNamePhysicalDnsHostname, uintptr(unsafe.Pointer(name))); r == 0 {
		// The object is renamed; only the local DNS name lagged. Reported
		// as a failure so it is seen, and the next attempt finds the
		// object already named and finishes this half.
		return Result{Status: StatusFailed, Error: "renamed in the domain, but setting the local name failed: " + e.Error()}
	}
	return Result{Status: StatusRenamed, Reboot: true}
}

// renameError names the rename failures worth expecting. Access denied is
// the one a narrowly delegated join account hits (design 0017 section 3.4).
func renameError(status uint32) string {
	switch status {
	case 5:
		return "access denied; the AD account may not rename computer objects in this OU (ERROR_ACCESS_DENIED)"
	}
	return joinError(status)
}

// joinError turns a NET_API_STATUS into something an admin can act on.
//
// The named ones are the failures worth expecting, and they are named
// because the generic text does not distinguish them: syscall.Errno renders
// 1355 as "The specified domain either does not exist or could not be
// contacted", which is right, but renders the NERR_* range (2100-2999) as an
// unknown error, and NERR_SetupAlreadyJoined is the single most likely thing
// to come back here.
func joinError(status uint32) string {
	switch status {
	case 2691:
		return "already joined to a domain (NERR_SetupAlreadyJoined)"
	case 2692:
		return "not joined to a domain (NERR_SetupNotJoined)"
	case 2695:
		return "the computer name is not valid for this domain (NERR_InvalidWorkgroupName)"
	case 1326:
		return "the join credential was rejected (ERROR_LOGON_FAILURE)"
	case 1355:
		return "the domain does not exist or could not be contacted (ERROR_NO_SUCH_DOMAIN)"
	case 8557:
		return "the OU does not exist or the account may not create objects in it (ERROR_DS_NO_SUCH_OBJECT)"
	case 5:
		return "access denied; the join account lacks rights on the target OU (ERROR_ACCESS_DENIED)"
	case nerrUserExists:
		return "the computer object already exists and could not be reused (NERR_UserExists)"
	case 2732:
		// KB5020276: reuse is allowed only to the object's creator, a
		// domain admin, or an account the GPO "Domain controller: Allow
		// computer account re-use during domain join" lists.
		return "the computer object exists and domain policy blocks this account from reusing it (NERR_AccountReuseBlockedByPolicy)"
	}
	return syscall.Errno(status).Error()
}

// JoinForPlan preserves the established Workgroup Join flags/reuse policy.
// Only a server-claimed concrete Deploy operation can enter this wrapper.
func JoinForPlan(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if plan.Version != 2 || plan.Operation != "join" || plan.Validate(plan.HostID) != nil {
		return 0, errors.New("invalid task join plan")
	}
	var code uint32
	err := withDirectoryMutation(func() error {
		var callErr error
		code, callErr = joinForPlanWindowsLocked(ctx, p, plan)
		return callErr
	})
	return code, err
}

func joinForPlanWindowsLocked(ctx context.Context, p Policy, plan RejoinPlan) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	o, err := ObserveRejoin(plan.DC)
	if err != nil || o.Domain != "" || !strings.EqualFold(o.CurrentName, plan.ExpectedCurrent) || !strings.EqualFold(o.PendingName, plan.Name) || (o.Role != "workstation" && o.Role != "member_server" && o.Role != "standalone_server") {
		return 0, errors.New("task join observation changed before native")
	}
	p.Domain = plan.Domain + `\` + plan.DC
	result := joinWindowsLocked(ctx, p)
	if result.Status != StatusJoined {
		return 0, errors.New("task join outcome requires review")
	}
	return 0, nil
}
