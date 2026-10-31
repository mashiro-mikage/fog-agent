package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/provider"
	"github.com/FOGProject/fog-agent/internal/provider/update"
	"github.com/FOGProject/fog-agent/internal/release"
)

// DefaultManifestURL is where this build looks for the signed release
// manifest when the server names no mirror. Stamped by the release build
// the way Version is (-X main.DefaultManifestURL=...), so a lab build can
// point somewhere else without a code change.
//
// Nothing about this URL is trusted. It is where to look, not what to
// believe: the manifest found there still has to be signed under a root
// compiled into this binary.
var DefaultManifestURL = "https://fogproject.org/version/agent-stable.json"

// firstSelfUpdatingVersion is the oldest version this build will agree to
// become, and it is the first version that carried self-update at all.
//
// The floor is not about state formats, it is about one-way doors: an
// agent downgraded below this can never be updated forward again by any
// mechanism it carries, because the version it landed on does not have
// this code. A downgrade that strands a fleet is not a rollback.
//
// It is 0.1.2 because that is the release self-update actually shipped in.
// It read 0.2.0 while 0.2.0 was still the expected next version, which had
// the effect of excluding the one released version that CAN be rolled back
// to: a downgrade is the only recovery from a build that installs, starts
// and polls perfectly well and then behaves badly (design 0015 §9, §11),
// and with the floor above every such version there was nothing left to
// recover to. Raise this only when a version is genuinely unable to carry
// a fleet forward, never in step with the current release.
const firstSelfUpdatingVersion = "0.1.2"

// probationWindow is how long a new binary has to complete one successful
// authenticated poll. Three poll intervals at the five-minute default:
// long enough that one missed poll is not a revert, short enough that a
// machine does not sit all day on a binary that cannot talk to its server.
const probationWindow = 15 * time.Minute

// updateConfig assembles what the update provider needs from this
// process: which binary it is, where its state lives, and what it is
// allowed to trust.
func updateConfig(st *enroll.State) update.Config {
	exe, err := os.Executable()
	if err != nil {
		// Without knowing which file we are, there is nothing to
		// replace. An empty path makes every swap fail rather than
		// guessing at one.
		exe = ""
	}
	roots, n := release.Roots()
	return update.Config{
		Current:            Version,
		GOOS:               runtime.GOOS,
		GOARCH:             runtime.GOARCH,
		Roots:              roots,
		RootCount:          n,
		DefaultManifestURL: DefaultManifestURL,
		MinDowngrade:       firstSelfUpdatingVersion,
		ExePath:            exe,
		StateDir:           st.Dir,
		Fetch:              update.HTTPFetch(manifestClient(st)),
		Now:                time.Now,
		Probation:          probationWindow,
		// Busy is nil: everything a reconcile does runs sequentially in
		// one goroutine and the update step runs last, so there is no
		// snapin child or package install in flight when it runs. If
		// anything in the reconcile ever becomes concurrent, this is the
		// line that has to change with it.
		Busy: nil,
	}
}

// updatePayload is the update provider's way to the server's copy of an
// artifact: the payload route, over the certificate this agent polls with,
// which is the path a snapin file already takes.
func updatePayload(client *enroll.Client) func(context.Context, int, io.Writer) error {
	return func(ctx context.Context, id int, w io.Writer) error {
		return client.Payload(ctx, "update", id, w)
	}
}

// manifestClient fetches the manifest and the artifact.
//
// It consults the system trust store whatever the server is trusted by, a
// deliberate, narrow exception to design 0002, where only a server on a
// public or corporate certificate is verified that way. The reason it costs
// nothing: TLS is not what is trusted
// here. The manifest carries its own signature and the artifact carries
// its own hash, so the transport is bandwidth and privacy hygiene rather
// than a trust decision -- which is exactly why it is safe to let the FOG
// server nominate a mirror. The server's own CA is added so that a site
// can host the mirror on the FOG server itself, the same exception design
// 0003 already makes for the Chocolatey bootstrap fetch.
func manifestClient(st *enroll.State) *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ca := st.CA(); len(ca) > 0 {
		pool.AppendCertsFromPEM(ca)
	}
	return &http.Client{
		Timeout: 10 * time.Minute, // a 10 MB binary over a school's uplink
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// checkProbation runs at start. A binary installed by an update has to
// prove itself, and this is the half of that which happens before it has
// had the chance: if the deadline has already passed, this binary has had
// its window and did not manage a successful poll in it.
//
// Returning true means the caller must exit non-zero so the service
// manager starts what was just restored.
func checkProbation(st *enroll.State, out *sayer) bool {
	return checkProbationWithRevert(st, out, func(reason string) error {
		_, err := update.Revert(updateConfig(st), reason)
		return err
	})
}

func checkProbationWithRevert(st *enroll.State, out *sayer, revert func(string) error) bool {
	p, err := update.LoadProbation(st.Dir)
	if err != nil {
		out.say("update: " + err.Error())
		return false
	}
	if p == nil {
		return false
	}
	if !p.Due(time.Now()) {
		out.say(fmt.Sprintf("update: on probation as %s until %s; one successful poll clears it",
			p.To, p.Deadline.Format(time.RFC3339)))
		return false
	}
	out.say(fmt.Sprintf("update: %s did not complete a poll before %s; going back to %s",
		p.To, p.Deadline.Format(time.RFC3339), p.From))
	if err := revert(fmt.Sprintf("no successful poll before %s", p.Deadline.Format(time.RFC3339))); err != nil {
		// Nothing else to try. Say it loudly rather than carrying on
		// quietly on a binary that has already failed its window.
		out.say("update: REVERT FAILED, this host is running " + p.To + " and needs attention: " + err.Error())
		return false
	}
	out.say("update: reverted to " + p.From)
	return true
}

// passedProbation is called after a poll has succeeded. That is the whole
// test: not that the binary starts, which the service manager already
// checks, but that it can still talk to the server that manages it.
func passedProbation(st *enroll.State, out *sayer) {
	p, err := update.LoadProbation(st.Dir)
	if err != nil || p == nil {
		return
	}
	if err := update.ClearProbation(st.Dir); err != nil {
		out.say("update: clearing probation: " + err.Error())
		return
	}
	out.say(fmt.Sprintf("update: %s polled successfully; %s -> %s is now the installed version", p.To, p.From, p.To))
}

// reportRevert tells the server about a revert that has already happened.
//
// Called after a poll has succeeded, for the same reason passedProbation
// is: the record was written by a binary that is no longer running, and
// the earliest anyone can say so is once the restored one is talking to
// the server again. It is the only way `agent.update.reverted` is ever
// recorded, and without it a bad release is invisible from the server --
// the hosts simply never arrive, which looks like a slow rollout.
//
// The record is cleared only when the server has taken the report. A
// failed send leaves it for the next poll; reporting a revert twice would
// be worse than reporting it late, but not sending it at all is worse than
// either.
func reportRevert(ctx context.Context, st *enroll.State, client *enroll.Client, out *sayer) {
	r, err := update.LoadReverted(st.Dir)
	if err != nil || r == nil {
		return
	}
	detail := fmt.Sprintf("reverted: %s -> %s", r.To, r.From)
	if r.Reason != "" {
		detail += " (" + r.Reason + ")"
	}
	if _, err := client.Result(ctx, enroll.ResultRequest{
		Revision:   st.Config.AppliedRevision,
		Capability: "update",
		Status:     provider.StatusFailed,
		Detail:     detail,
	}); err != nil {
		out.say("result: " + err.Error())
		return
	}
	if err := update.ClearReverted(st.Dir); err != nil {
		out.say("update: clearing the revert report: " + err.Error())
	}
}

// cmdUpdateRevert is what the service manager runs when the new binary
// has failed to start enough times to stop being a transient, and what a
// person runs with hands on the machine. It is deliberately a separate
// command: the code that reverts must not be inside the process that is
// too broken to run.
func cmdUpdateRevert(args []string) error {
	dir := dirArg(args)
	st, err := enroll.Load(dir)
	if err != nil {
		return err
	}
	// Named for what actually invoked this, which is the distinction
	// that matters when reading it back: the deadline path above means
	// the new binary ran but never reached the server, while this one
	// means it could not stay running at all -- or that somebody was
	// standing at the machine.
	p, err := update.Revert(updateConfig(st), "restart limit or run by hand")
	if err != nil {
		return err
	}
	fmt.Printf("reverted %s -> %s\n", p.To, p.From)
	return nil
}

// has reports whether the server offered this capability.
func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// cmdUpdate applies a version by hand, the way `fog-agent renew` forces a
// renewal that would otherwise wait for its window.
//
// It exists for the same two reasons renew does: an admin standing at a
// machine should not have to wait for a poll to make something happen, and
// the mechanism should be exercisable without a server being involved. It
// takes the same path the server-driven update takes -- the same
// verification, the same rollback arming, the same swap -- because a
// hands-on path that skipped any of those would be a way to install an
// unverified binary, which is the one thing this design exists to prevent.
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	dir := fs.String("dir", enroll.DefaultDir, "state directory")
	to := fs.String("to", "", "the version to become (required)")
	url := fs.String("manifest", "", "override the release manifest URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" {
		return errors.New("update: --to VERSION is required; there is deliberately no \"latest\"")
	}
	st, err := enroll.Load(*dir)
	if err != nil {
		return err
	}
	out := &sayer{}
	r, restart := update.Run(context.Background(),
		update.Desired{Version: *to, ManifestURL: *url}, updateConfig(st))
	out.say(fmt.Sprintf("update: %s (%s)", r.Status, r.Detail))
	if r.Status == provider.StatusFailed {
		return errors.New(r.Detail)
	}
	if restart {
		// Same contract as the service path: the binary under this
		// process is not the one that started it, so say so and leave
		// non-zero. A person running this by hand restarts the service;
		// under the service manager, the non-zero exit IS the restart.
		return errUpdated
	}
	return nil
}
