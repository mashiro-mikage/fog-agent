// Package directoryjoin is the directory capability's acting half (design
// 0009 §6): joining a machine to the domain the host record asks for.
//
// It JOINS, and it RENAMES a member of the target domain (design 0017). It
// never unjoins, and it never re-joins a machine that is already in the
// target domain. Leaving a domain stays a deliberate,
// separately-expressed act, because the cost is real and asymmetric: a
// rejoin resets the computer account's password and, where the object is
// recreated, gives the machine a new SID -- losing its group memberships,
// its escrowed BitLocker keys, its LAPS password and any certificate issued
// to it. None of that may ever be a side effect of an admin editing a field.
//
// The other half, moving an already-joined machine's computer object between
// OUs, is NOT here: that is a property of an object in a directory, so the
// server does it with one LDAP Modify DN and the machine is not involved
// (design 0009 §5, FOG\Agent\DirectoryPlacement). The OU on this side is
// only the container the object is CREATED in, which saves a move that would
// otherwise have to follow every first join.
package directoryjoin

import (
	"context"
	"strings"

	"github.com/FOGProject/fog-agent/internal/directory"
	"github.com/FOGProject/fog-agent/internal/secret"
)

// What the agent reports for a join. These are the server's
// DirectoryJoin::STATUSES.
const (
	// StatusJoined is a join this run performed.
	StatusJoined = "joined"
	// StatusAlreadyJoined is the resting state: the machine is in the
	// domain it should be in and nothing was attempted.
	StatusAlreadyJoined = "already_joined"
	// StatusRenamed is a rename in the domain that is done and waits on a
	// restart: this run performed it, or an earlier one did and the
	// machine has not restarted yet.
	StatusRenamed = "renamed"
	// StatusFailed is an attempt that did not work; the message says why.
	StatusFailed = "failed"
	// StatusUnsupported is no join tooling on this platform.
	StatusUnsupported = "unsupported"
	// StatusRefused is the agent declining to act on what it was sent --
	// a machine already in a DIFFERENT domain, or a policy with no
	// credential. Kept apart from failed because nothing was tried and
	// nothing about the machine or the directory is wrong.
	StatusRefused = "refused"
)

// MaxError is how much of a tool's message is worth sending: the server
// column is a varchar(255), and this is a line an admin reads in a report.
const MaxError = 255

// Policy is the directory block of the desired state.
//
// It arrives only for a host that the server believes is NOT joined and has
// a domain configured -- so a joined estate, which is most of an estate most
// of the time, never carries a join credential at all.
type Policy struct {
	Rejoin *RejoinPlan `json:"rejoin,omitempty"`
	// Domain is the DNS domain to join: corp.example.com.
	Domain string `json:"domain"`
	// Netbios is the short name, where the server knows it. Used only to
	// recognize that the machine is already in this domain when a platform
	// reports the short form; never used to join.
	Netbios string `json:"netbios"`
	// OU is the container the computer object is created in, as a DN.
	// Empty means the domain's default (CN=Computers), and the server's
	// placement half moves it afterwards.
	OU string `json:"ou"`
	// Username is the joining account, domain-qualified by the server.
	Username string `json:"username"`
	// Password is the joining account's password. Redacts itself under
	// every printer and marshaler in the process (internal/secret): it is
	// never written to the state directory and never logged.
	Password secret.Secret `json:"password"`
	// Reboot is the host's "Enforce Hostname | AD Join Reboots" flag: the
	// join's reboot is forced, even with a user logged in. Unset, the
	// reboot still happens, once nobody is logged in. The reboot
	// coordinator owns the when.
	Reboot bool `json:"reboot"`
	// RenameTo is set only for a machine already in this domain whose
	// computer object does not carry the host's name (design 0017). The
	// server sends the credential to a joined machine for this and nothing
	// else. Empty means "join".
	RenameTo string `json:"rename_to"`
}

// Names is what the machine is called now and after its next boot.
type Names struct {
	// Current is the name the machine runs under.
	Current string
	// Pending is the name set for the next boot; empty when none is, or
	// when the platform has no such thing.
	Pending string
}

// Action is what convergence decided.
type Action int

// The actions.
const (
	// None is "the machine is where it should be".
	None Action = iota
	// Join is "join it".
	Join
	// Refuse is "do not act, and say why" -- distinct from None, which is
	// a good resting state, and from a failed attempt.
	Refuse
	// Rename is "rename the machine and its computer object together".
	Rename
	// Renamed is "that rename is already done and waits on a restart":
	// report it, and do not make the call again.
	Renamed
)

func (a Action) String() string {
	switch a {
	case Join:
		return "join"
	case Refuse:
		return "refuse"
	case Rename:
		return "rename"
	case Renamed:
		return "renamed"
	}
	return "none"
}

// Result is what a backend came back with.
type Result struct {
	Status string
	Error  string
	// NativeStatus preserves a definite native failure without treating a
	// partially completed local name update as a replayable failure.
	NativeStatus uint32
	// Reboot is set when the platform needs one for the join to take
	// effect. Windows always does; Linux does not.
	Reboot bool
}

// Backend performs the join on one platform.
type Backend interface {
	// Available says whether a join can be attempted here at all; the
	// detail names what is missing when it cannot.
	Available() (bool, string)
	// Join adds the machine to the domain.
	Join(ctx context.Context, p Policy) Result
	// Rename renames a member of the domain and its computer object to
	// p.RenameTo.
	Rename(ctx context.Context, p Policy) Result
}

// Decide is the rule, pure so every row of it is a test case.
//
// The refusals are the interesting part, and each one is a thing that would
// otherwise be silent damage:
//
//   - A machine already in a DIFFERENT domain is refused, not moved. Getting
//     there means leaving the first domain, which this package never does.
//     An admin who genuinely wants that does it deliberately, and sees this
//     message in the report until they do.
//   - A policy with no credential is refused rather than attempted, because
//     an unauthenticated join attempt is a failed authentication against
//     somebody's domain controller, repeated once a poll.
//   - An empty domain is refused for the same reason it is on the server:
//     there is nothing to join, and guessing is worse than saying so.
//
// A rename is decided against names, not against the server's belief: the
// server cannot see a rename until the machine restarts and reports its new
// account, so it may send the same rename twice. A name already pending is
// reported, not renamed again.
func Decide(p Policy, observed directory.Directory, names Names) (Action, string) {
	want := strings.ToLower(strings.TrimSpace(p.Domain))
	if want == "" {
		return Refuse, "no domain to join: set one on the host"
	}
	if observed.Joined && sameDomain(observed, want, p.Netbios) {
		to := strings.TrimSpace(p.RenameTo)
		switch {
		case to == "" || strings.EqualFold(names.Current, to):
			return None, "already in " + want
		case names.Pending != "" && strings.EqualFold(names.Pending, to):
			return Renamed, "renamed to " + to + " in " + want + "; a restart finishes it"
		case strings.TrimSpace(p.Username) == "" || p.Password.Empty():
			return Refuse, "no credential to rename this machine in " + want +
				": set the AD username and password on the host"
		}
		return Rename, "renaming " + names.Current + " to " + to + " in " + want
	}
	if observed.Joined {
		// The one that must never become an unjoin.
		return Refuse, "already joined to " + observed.Domain +
			", not " + want + "; leaving a domain is not something FOG does for you"
	}
	if strings.TrimSpace(p.Username) == "" || p.Password.Empty() {
		return Refuse, "no join credential: set the AD username and password on the host"
	}
	return Join, "not joined; joining " + want
}

// sameDomain compares what the machine reported against what is wanted.
//
// Both forms count, because FOG's hostADDomain has always held whichever one
// the admin typed: a machine reporting the DNS name matches a policy naming
// the DNS name, and one reporting only the short name matches the short name
// the server resolved. Getting this wrong in the strict direction is not a
// cosmetic bug -- it would read a correctly joined machine as unjoined and
// try to join it again on every poll, against a live domain controller.
func sameDomain(observed directory.Directory, want, netbios string) bool {
	if strings.EqualFold(observed.Domain, want) {
		return true
	}
	// The short name only counts when the server actually knows it; an
	// empty netbios must not match an empty observed one.
	netbios = strings.TrimSpace(netbios)
	if netbios != "" && strings.EqualFold(observed.Netbios, netbios) {
		return true
	}
	// A policy naming the short form, from either side: hostADDomain may
	// hold `CORP` where the machine reports `corp.example.com`, or the
	// reverse. Both are the same domain and neither is a reason to re-join.
	if observed.Netbios == "" {
		return false
	}
	if i := strings.Index(want, "."); i > 0 {
		return strings.EqualFold(observed.Netbios, want[:i])
	}
	return strings.EqualFold(observed.Netbios, want)
}

// Report is what happened, ready to send.
type Report struct {
	Status string
	Error  string
	// Detail is the human line for the agent's own log. It never contains
	// the credential: nothing here formats the Policy.
	Detail string
	// Reboot is set when the platform needs one for the join to take
	// effect.
	Reboot bool
	// Force is the host's enforce flag (Policy.Reboot): reboot even if
	// someone is logged in.
	Force bool
}

// Converge joins the machine if it should be, and reports what happened
// either way -- including the resting state, because the server reads
// already_joined as "still true" and silence as unknown.
//
// The policy's credential is zeroed on the way out. That is a narrowing
// rather than a guarantee (Go strings are immutable and the collector may
// have copied the bytes), but it means the struct a caller still holds after
// this returns cannot print or persist the value.
// The policy is taken by POINTER for exactly one reason: so the zeroing
// reaches the caller's copy. A value receiver would zero a copy this
// function is about to discard anyway, which looks like the credential was
// dropped and is not.
func Converge(ctx context.Context, backend Backend, p *Policy, observed directory.Directory, names Names) Report {
	defer p.Password.Zero()

	action, why := Decide(*p, observed, names)
	switch action {
	case Refuse:
		return Report{Status: StatusRefused, Error: truncate(why), Detail: why}
	case None:
		return Report{Status: StatusAlreadyJoined, Detail: why}
	case Renamed:
		return Report{Status: StatusRenamed, Detail: why}
	}

	if ok, missing := backend.Available(); !ok {
		return Report{Status: StatusUnsupported, Error: truncate(missing), Detail: missing}
	}

	if action == Rename {
		// No reboot asked for here. The hostname capability sees the new
		// name pending and asks for it under the host's enforce flag, as
		// it does for any rename.
		res := backend.Rename(ctx, *p)
		return Report{Status: res.Status, Error: truncate(res.Error), Detail: why}
	}

	res := backend.Join(ctx, *p)
	return Report{
		Status: res.Status,
		Error:  truncate(res.Error),
		Detail: why,
		// The host's enforce flag decides whether the reboot waits for
		// logged-in users; the reboot coordinator decides when.
		Reboot: res.Reboot,
		Force:  p.Reboot,
	}
}

// truncate keeps a message to what the server's column holds.
func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= MaxError {
		return s
	}
	return s[:MaxError]
}
