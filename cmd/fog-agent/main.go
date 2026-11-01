// fog-agent is the FOG management agent. Today it reports identity, enrolls
// and polls; the providers follow the design in
// docs/design/0001-architecture.md.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/FOGProject/fog-agent/internal/directory"
	"github.com/FOGProject/fog-agent/internal/enroll"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/netboot"
	"github.com/FOGProject/fog-agent/internal/printers"
	"github.com/FOGProject/fog-agent/internal/provider"
	"github.com/FOGProject/fog-agent/internal/provider/activation"
	"github.com/FOGProject/fog-agent/internal/provider/autologout"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
	"github.com/FOGProject/fog-agent/internal/provider/hostname"
	"github.com/FOGProject/fog-agent/internal/provider/power"
	"github.com/FOGProject/fog-agent/internal/provider/printerset"
	"github.com/FOGProject/fog-agent/internal/provider/snapin"
	"github.com/FOGProject/fog-agent/internal/provider/software"
	"github.com/FOGProject/fog-agent/internal/provider/update"
	"github.com/FOGProject/fog-agent/internal/provider/wake"
	"github.com/FOGProject/fog-agent/internal/reboot"
)

// Version is stamped by the release build (-ldflags "-X main.Version=...").
var Version = "dev"

func main() {
	// Under the Windows service control manager there is no terminal:
	// the same run loop, with the log in a file and a stop request
	// canceling the context (service_windows.go).
	if isService() {
		if err := runService(); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "identity":
		err = printJSON(identity.Read())
	case "version":
		fmt.Printf("fog-agent %s %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "renew":
		err = cmdRenew(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "update-revert":
		err = cmdUpdateRevert(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(logOut, "fog-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  fog-agent identity                      print the SMBIOS identity and MACs
  fog-agent enroll --server URL --ca FILE [--token T] [--once] [--dir DIR] [--reset-identity]
  fog-agent run [--server URL] [--ca FILE] [--token T] [--once] [--dir DIR]
                                          enroll if needed, then poll the server
  fog-agent renew [--dir DIR]             renew the certificate now, whatever its expiry
  fog-agent update --to VERSION           verify and apply a version now, without waiting for a poll
  fog-agent update-revert [--dir DIR]     put back the binary an update replaced
  fog-agent status [--dir DIR]
  fog-agent ca probe --server URL         show what the agent would trust for the server
  fog-agent service install --server URL [--ca-fingerprint FP | --ca FILE] [--token T] [--dir DIR]
  fog-agent setup --server URL [--ca-fingerprint FP | --ca FILE] [--token T] [--dir DIR]
                                          Windows: install and start the service
  --server is asked for at the prompt when "service install" or "setup" is
  run without it. The agent then asks the server what to trust. A server
  on FOG's own certificates shows a fingerprint to confirm; unattended,
  pass it as --ca-fingerprint. A server on a public or corporate
  certificate this machine already trusts needs nothing more. --ca FILE
  pins a CA file instead, for a CA this machine does not trust.
  fog-agent service uninstall|start|stop|status
  fog-agent version`)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// logOut is where the agent talks: stderr from a terminal, the log file
// under the service (runService swaps it before anything is said).
var logOut io.Writer = os.Stderr

// sayer prints a line only when it changes, so a loop that repeats the
// same state every few minutes writes one line per change of state, not
// one per iteration (design doc 5.1: informative, never noisy). Under
// the service each line is stamped, since nothing else dates it.
type sayer struct{ last string }

func (s *sayer) say(msg string) {
	if msg != s.last {
		if logOut != os.Stderr {
			msg = time.Now().Format(time.RFC3339) + " " + msg
		}
		fmt.Fprintln(logOut, msg)
		s.last = msg
	}
}

// commonFlags are shared by enroll and run.
type commonFlags struct {
	server, caPath, token, dir *string
	// caFingerprint pins what the server is allowed to publish when no CA
	// file is given, so an unattended install can fetch the anchor without
	// trusting whatever answers.
	caFingerprint *string
}

func addCommonFlags(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		server:        fs.String("server", "", "FOG server base URL, e.g. https://fog.example.org/fog (remembered after the first enroll)"),
		caPath:        fs.String("ca", "", "PEM or DER CA certificate to pin for the server instead of asking it, for a CA this machine does not trust (remembered)"),
		caFingerprint: fs.String("ca-fingerprint", "", "SHA-256 of the certificate the server publishes; with this and no --ca the agent fetches it and refuses anything else"),
		token:         fs.String("token", "", "enrollment token minted by an admin (optional)"),
		dir:           fs.String("dir", enroll.DefaultDir, "state directory"),
	}
}

// openState loads the state directory and settles the server URL and what
// to trust for it, from flags or from what an earlier enroll remembered.
func openState(f commonFlags) (*enroll.State, error) {
	st, err := enroll.Load(*f.dir)
	if err != nil {
		return nil, err
	}
	if *f.server != "" {
		st.Config.ServerURL = *f.server
	}
	if st.Config.ServerURL == "" {
		return nil, errors.New("--server is required the first time")
	}
	if *f.caPath != "" {
		caPEM, err := enroll.ReadCABundle(*f.caPath)
		if err != nil {
			return nil, err
		}
		if err := st.SaveCA(caPEM); err != nil {
			return nil, err
		}
	}
	if !st.HasTrust() {
		// No file, and nothing remembered: ask the server. Only here, so an
		// agent that pinned a CA never falls back to this machine's trust
		// store when that CA stops verifying. acquireCA settles neither a
		// bundle nor system trust when a FOG CA has nobody to confirm it,
		// and the error below is then the honest one.
		caPEM, system, err := acquireCA(f, st.Config.ServerURL)
		if err != nil {
			return nil, err
		}
		switch {
		case system:
			if err := st.UseSystemTrust(); err != nil {
				return nil, err
			}
		case len(caPEM) > 0:
			if err := st.SaveCA(caPEM); err != nil {
				return nil, err
			}
		}
	}
	if !st.HasTrust() {
		return nil, errors.New("nothing to trust for the server yet: its certificate is issued by the CA it publishes, " +
			"and nothing confirmed that CA. Pass --ca-fingerprint with the SHA-256 from FOG Configuration -> Certificates, or --ca with the CA file")
	}
	if err := st.SaveConfig(); err != nil {
		return nil, err
	}
	return st, nil
}

// readIdentity reads the live SMBIOS identity. A variable so a test can
// present a machine other than the one it runs on.
var readIdentity = identity.Read

// enrollRequest reads the machine's identity, settles the key for it and
// builds the request protocol-v1.md describes.
func enrollRequest(st *enroll.State, token string, out *sayer) (enroll.Request, error) {
	live := readIdentity()
	regen := false
	var err error
	if runtime.GOOS != "windows" {
		regen, err = st.EnsureKey(live)
	} else if st.Key == nil {
		err = errors.New("directory identity must be prepared before enrollment")
	}
	if err != nil {
		return enroll.Request{}, err
	}
	if regen {
		out.say("generated a new key for this machine's identity")
	}
	csr, err := st.CSR()
	if err != nil {
		return enroll.Request{}, err
	}
	hostname, _ := os.Hostname()
	var features []string
	if runtime.GOOS == "windows" {
		features = []string{enroll.DirectoryJoinTargetFeature}
	}
	return enroll.Request{
		Features: features,
		Protocol: enroll.Protocol, AgentVersion: Version,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname,
		Identity: live, CSRPEM: string(csr), Token: token,
	}, nil
}

// enrollLoop repeats the same request until the server issues, and keeps
// repeating on a slower cadence when denied so a later approval is still
// reachable. With once set it returns after a single exchange, issued or
// not, and the caller prints the answer.
func enrollLoop(ctx context.Context, st *enroll.State, client *enroll.Client, req enroll.Request, once bool, out *sayer) (*enroll.Response, error) {
	for {
		resp, err := client.Enroll(ctx, req)
		wait := 5 * time.Minute
		switch {
		case err != nil:
			out.say("enroll: " + err.Error())
		case resp.Status == enroll.StatusIssued:
			// The token, if one was kept for this attempt, is spent.
			st.Config.PendingToken = ""
			if err := st.SaveIssued([]byte(resp.CertificatePEM), resp.HostID); err != nil {
				return nil, err
			}
			if err := st.SaveConfig(); err != nil {
				return nil, err
			}
			out.say(fmt.Sprintf("enrolled as host %d, certificate valid until %s", resp.HostID, resp.NotAfter))
			return resp, nil
		case resp.Status == enroll.StatusPending:
			out.say(fmt.Sprintf("pending approval on the server (%s); waiting", resp.Reason))
			if resp.RetryAfter > 0 {
				wait = time.Duration(resp.RetryAfter) * time.Second
			}
		case resp.Status == enroll.StatusDenied:
			out.say(fmt.Sprintf("denied by the server (%s); retrying hourly", resp.Reason))
			wait = time.Hour
		default:
			out.say("server does not support agent protocol 1; retrying hourly")
			wait = time.Hour
		}
		if once {
			return resp, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	f := addCommonFlags(fs)
	once := fs.Bool("once", false, "send one request and exit instead of waiting for approval")
	reset := fs.Bool("reset-identity", false, "explicit administrator reset; stop the service first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openState(f)
	if err != nil {
		return err
	}
	out := &sayer{}
	if runtime.GOOS == "windows" {
		probe, e := st.Client()
		if e != nil {
			return e
		}
		if e = probe.RequireDirectoryFeatures(context.Background()); e != nil {
			return e
		}
		if *reset {
			if e = allowIdentityReset(); e != nil {
				return e
			}
			// An operator reset is not proof that the saved Host was the clone source.
			if e = st.RotateIdentity(readIdentity()); e != nil {
				return e
			}
		}
		if e = prepareDirectoryIdentity(context.Background(), st, probe); e != nil {
			return e
		}
	} else if *reset {
		return errors.New("identity reset is supported on Windows only")
	}
	req, err := enrollRequest(st, *f.token, out)
	if err != nil {
		return err
	}
	client, err := st.Client()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	resp, err := enrollLoop(ctx, st, client, req, *once, out)
	if err != nil {
		return err
	}
	if *once {
		return printJSON(resp)
	}
	return nil
}

// cmdRun is the service loop: enroll if there is no certificate, then poll
// with it. A 401 from the poll means the server no longer knows this
// certificate -- the host was deleted, or re-enrolled from elsewhere -- so
// the agent drops it and goes back to enrolling, where it will be pended
// for an admin like any unknown machine.
func cmdRun(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAgent(ctx, args)
}

// runAgent is the agent: enroll if needed, then poll until ctx ends. The
// command line gives it an interrupt context; the Windows service gives it
// one the service control manager cancels.
func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	f := addCommonFlags(fs)
	once := fs.Bool("once", false, "one poll (enrolling first if needed), print the answer and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openState(f)
	if err != nil {
		return err
	}
	client, err := st.Client()
	if err != nil {
		return err
	}
	out := &sayer{}
	// The clone and reimage guard (design doc 4.4) runs on every start, not
	// only on the way into an enrollment. A captured image carries the
	// certificate as well as the key, so a clone never went that way: it
	// polled as the machine the image was captured from, and applied that
	// host's name, tasks and snapins to itself.
	if runtime.GOOS == "windows" {
		if err = prepareWindowsRun(ctx, st, client, out); err != nil {
			return err
		}
	} else {
		hadKey := st.Key != nil
		regen, e := st.EnsureKey(readIdentity())
		if e != nil {
			return e
		}
		if regen && hadKey {
			out.say("cloned or reimaged disk: enrolling this machine")
		}
	}
	identityVerified := false
	identitySignature := ""
	watch := &sessionWatcher{}
	for {
		// Checked every time round, not only at start. A binary that
		// crashes is the service manager's problem and it has recovery
		// actions for it; the case this catches is the quieter one --
		// a binary that starts perfectly well, runs for hours and
		// cannot talk to its server. Evaluating the deadline only at
		// startup would leave that host up on a broken version until
		// something else happened to restart it, which on a machine
		// nobody logs into is "until somebody notices".
		if checkProbation(st, out) {
			return errUpdated
		}
		if len(st.Cert) == 0 {
			// A token setup kept for us outranks nothing on the command
			// line: the service is registered with plain `run`.
			token := *f.token
			if token == "" {
				token = st.Config.PendingToken
			}
			req, err := enrollRequest(st, token, out)
			if err != nil {
				return err
			}
			resp, err := enrollLoop(ctx, st, client, req, *once, out)
			if err != nil {
				return err
			}
			if *once && resp.Status != enroll.StatusIssued {
				return printJSON(resp)
			}
		}
		if err := client.UseCertificate(st.Cert, st.Key); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			live := readIdentity()
			encoded, _ := json.Marshal(live)
			if !identityVerified || identitySignature != string(encoded) {
				a, e := client.CheckIdentity(ctx, live)
				if e != nil {
					return e
				}
				if a.Identity.Status == "mismatch" {
					if e = st.RotateIdentity(live); e != nil {
						return e
					}
					identityVerified = false
					continue
				}
				identityVerified = true
				identitySignature = string(encoded)
			}
		}
		wait := 5 * time.Minute
		// The poll carries what this agent applied; the server answers
		directoryCheckChanged := false
		// with the state only when that is not current. A build that
		// learned a capability sends nothing, so it gets the state once.
		req := enroll.PollRequest{AgentVersion: Version, AppliedRevision: st.Config.AppliedRevision, WantState: driftMayBeDue(st)}
		attachDirectoryContext(st, &req)
		if st.Config.AppliedWith != supportedCapabilities {
			req.AppliedRevision = ""
		}
		// Facts ride up the same request the desired state comes down
		// (design 0006): sent only when their hash moved or the server
		// asked, and recorded only once the poll has succeeded.
		now := time.Now()
		sent := attachFacts(st, &req, now, out)
		sessionDigest, sessionsSent := watch.attach(st, &req, now)
		resp, err := client.Poll(ctx, req)
		if err == nil && runtime.GOOS == "windows" {
			if changed, e := refreshDirectoryCheck(st, resp.DirectoryCheck); e != nil {
				out.say("directory observation: " + e.Error())
			} else {
				directoryCheckChanged = changed
			}
			operationBlocked := false
			if e := processRejoin(ctx, st, client, resp.DirectoryRejoin, out); e != nil {
				out.say("directory rejoin: " + e.Error())
				operationBlocked = true
			}
			if (resp.DirectoryHold || operationBlocked || resp.DirectoryRejoin != nil) && resp.State != nil {
				resp.State.Directory = nil
				resp.State.Hostname = nil
			}
		}
		switch {
		case errors.Is(err, enroll.ErrCertificateUnknown):
			// The server has this certificate and says it binds to no
			// host. That is the one 401 worth acting on.
			out.say("server no longer recognizes this certificate; enrolling again")
			if err := st.DropIssued(); err != nil {
				return err
			}
			if *once {
				return err
			}
			continue
		case errors.Is(err, enroll.ErrUnauthorized):
			// A 401 that is NOT about this binding: no certificate reached
			// the application, the database was down, a proxy answered, or
			// the webroot does not serve the agent routes. The certificate
			// is probably fine and re-enrolling would need an admin to
			// approve this host again, so keep it and keep asking.
			drop, err := unauthorizedTooLong(st, now)
			if err != nil {
				return err
			}
			if !drop {
				out.say("server refused this certificate (" + unauthorizedFor(st, now) +
					"); keeping it and retrying")
				if *once {
					return enroll.ErrUnauthorized
				}
				// NOT continue. This branch changes nothing -- the
				// certificate is kept and the next poll is byte for byte
				// the same request -- so skipping the wait at the bottom
				// of the loop retries the identical failing call as fast
				// as the network answers. Observed on telliottwin11 over a
				// six-minute window while the webroot was mid-deploy:
				// 15,100 identical lines, 1.37 MB of log, every one of
				// them stamped the same second.
				//
				// break leaves the switch, not the loop, so control
				// reaches waitOrFire like any other poll outcome. Falling
				// out of this if would run the drop path below instead.
				break
			}
			out.say("server has refused this certificate for " + unauthorizedFor(st, now) +
				"; enrolling again")
			if err := st.DropIssued(); err != nil {
				return err
			}
			if *once {
				return enroll.ErrUnauthorized
			}
			continue
		case err != nil:
			out.say("poll: " + err.Error())
		default:
			// A poll got through, so any run of refusals is over: it must
			// not carry over toward the grace period of a later, unrelated
			// outage.
			if err := clearUnauthorized(st); err != nil {
				out.say("state: " + err.Error())
			}
			// A poll got through, which is the whole of the probation
			// test: not that this binary starts, which the service
			// manager already checks, but that it can still talk to the
			// server that manages it.
			passedProbation(st, out)
			// A revert that already happened, reported by the binary it
			// restored. Next to passedProbation because the two are the
			// same fact from opposite ends -- this update worked out, or
			// it did not -- and both are only sayable once a poll has
			// got through.
			reportRevert(ctx, st, client, out)
			if resp.State != nil {
				out.say(fmt.Sprintf("host %d (%s), server capabilities: [%s]", resp.Host.ID, resp.Host.Name, strings.Join(resp.State.Capabilities, " ")))
			}
			if resp.PollInterval > 0 {
				wait = time.Duration(resp.PollInterval) * time.Second
			}
			if err := recordSessions(st, sessionDigest, sessionsSent, resp, now); err != nil {
				out.say("state: " + err.Error())
			}
			if err := recordFacts(st, sent, resp, now); err != nil {
				out.say("facts: " + err.Error())
			}
			// Renewal rides the same session, once the poll has proved
			// it. A failed renewal is reported and retried next poll;
			// the current certificate keeps working until it expires.
			if enroll.RenewDue(st.Cert, time.Now()) {
				if err := renew(ctx, st, client, out); err != nil {
					out.say("renew: " + err.Error())
				}
			}
			// Converge when the server's revision is not the one this
			// agent last applied. A failure leaves the revision
			// unapplied, so the next poll tries again.
			switch {
			case needsReconcile(st.Config, resp.Revision) && resp.State == nil:
				out.say("poll: the revision moved but the server sent no state")
			case needsReconcile(st.Config, resp.Revision):
				if err := reconcile(ctx, st, client, resp.State, out); err != nil {
					if errors.Is(err, errUpdated) {
						// The binary under this process is no longer the
						// one that started it. Leave with a non-zero
						// status so the service manager starts the new
						// one; that is the same recovery path a crashing
						// new binary takes, deliberately (design 0015 §6).
						//
						// Nothing is logged here. The update provider has
						// already said "applied (X -> Y, restarting)",
						// which names the versions; repeating the
						// sentinel added a second line saying the same
						// thing in fewer words, and on Windows the
						// service handler adds a third at the moment the
						// process actually goes.
						return err
					}
					out.say("reconcile: " + err.Error())
				}
			case resp.State != nil && driftMayBeDue(st):
				// The drift check: the set has not changed, the host
				// might have. The interval is the one the last
				// reconcile saw, so this costs nothing until it is due.
				if err := drift(ctx, st, client, resp.State, out); err != nil {
					out.say("software drift: " + err.Error())
				}
			}
			// The coordinator runs every poll, not only when state
			// moved: a reboot deferred for a logged-in user becomes
			// due when they leave, and nothing else notices that.
			if err := coordinate(ctx, st, client, out); err != nil {
				out.say("reboot: " + err.Error())
			}
			if *once {
				return printJSON(resp)
			}
		}
		if *once {
			return err
		}
		if directoryCheckChanged && wait > 2*time.Second {
			wait = 2 * time.Second
		}
		// Sleep until the poll is due or a power schedule fires,
		// whichever is first; a firing runs the coordinator right away.
		if fired, err := waitOrFire(ctx, st, client, wait, watch, out); err != nil {
			return err
		} else if fired {
			continue
		}
	}
}

// waitOrFire sleeps for wait unless a power schedule is due sooner, in
// which case it records the firing, hands the coordinator a forced
// reason and runs it, and reports true so the loop polls again at once
// (a shutdown that went through never returns here).
func waitOrFire(ctx context.Context, st *enroll.State, client *enroll.Client, wait time.Duration, watch *sessionWatcher, out *sayer) (bool, error) {
	now := time.Now()
	after := now
	if st.Config.PowerFired.After(after) {
		after = st.Config.PowerFired
	}
	next, sched, ok := power.Next(st.Config.PowerSchedules, after)
	if !ok || next.Sub(now) >= wait {
		if err := sleepSampling(ctx, st, watch, wait, out); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := sleepSampling(ctx, st, watch, next.Sub(now), out); err != nil {
		return false, err
	}
	st.Config.PowerFired = next
	st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
		Source: "power", Detail: fmt.Sprintf("scheduled %s (%s)", sched.Action, sched.Cron), Force: true, Mode: sched.Action,
	})
	if err := st.SaveConfig(); err != nil {
		return false, err
	}
	out.say(fmt.Sprintf("power: scheduled %s (%s) is due", sched.Action, sched.Cron))
	if err := coordinate(ctx, st, client, out); err != nil {
		out.say("reboot: " + err.Error())
	}
	return true, nil
}

// renew asks for a new certificate for the current key and switches the
// client to it. The old certificate is not touched until the new one is
// on disk, so a failure anywhere leaves the agent as it was.
func renew(ctx context.Context, st *enroll.State, client *enroll.Client, out *sayer) error {
	csr, err := st.CSR()
	if err != nil {
		return err
	}
	resp, err := client.Renew(ctx, csr)
	if err != nil {
		return err
	}
	if err := st.SaveIssued([]byte(resp.CertificatePEM), resp.HostID); err != nil {
		return err
	}
	if err := client.UseCertificate(st.Cert, st.Key); err != nil {
		return err
	}
	out.say(fmt.Sprintf("certificate renewed, valid until %s", resp.NotAfter))
	return nil
}

// reconcile runs every provider the server listed in the desired state,
// reporting each result. The revision is recorded as applied only
// when nothing failed: a failed provider is retried on the next poll
// rather than forgotten.
// capabilityOrder is the server's order, with one exception: a rename in
// the domain runs `directory` before `hostname` (design 0017). The rename
// leaves the new name pending, and hostname then reports the reboot in the
// same poll instead of failing first. A join keeps the server's order,
// hostname first, so the join runs under the name already pending.
func capabilityOrder(desired *enroll.DesiredState) []string {
	caps := desired.Capabilities
	if desired.Directory == nil || strings.TrimSpace(desired.Directory.RenameTo) == "" ||
		!slices.Contains(caps, "directory") {
		return caps
	}
	out := []string{"directory"}
	for _, c := range caps {
		if c != "directory" {
			out = append(out, c)
		}
	}
	return out
}

// errUpdated is how reconcile says the binary under this process is no
// longer the one that started it. Not an error in the ordinary sense: the
// process must now exit non-zero so the service manager starts the new
// binary, which is the same mechanism that recovers from a new binary
// that crashes on start (design 0015 section 6).
var errUpdated = errors.New("the agent replaced itself; restarting")

func reconcile(ctx context.Context, st *enroll.State, client *enroll.Client, desired *enroll.DesiredState, out *sayer) error {
	if desired.Reboot != nil {
		st.Config.RebootGrace = desired.Reboot.Grace
	}
	allOK := true
	for _, capability := range capabilityOrder(desired) {
		var r provider.Result
		force := false
		switch capability {
		case "hostname":
			if desired.Hostname == nil {
				continue
			}
			r = hostname.Ensure(*desired.Hostname)
			force = desired.Hostname.Enforce
		case "activation":
			// Design 0016: install the host's product key and activate.
			// A failed install holds the revision and is tried again next
			// poll; an activation Windows could not finish is applied,
			// because Windows retries that itself.
			if desired.Activation == nil {
				continue
			}
			r = activation.Ensure(ctx, *desired.Activation)
		case "taskreboot":
			// Not a provider: a waiting task is a reboot request, and
			// a cancelled one withdraws it. The coordinator acts on it
			// below, under the same policy as everything else.
			if desired.Task == nil || desired.Task.ID == st.Config.RebootedForTask {
				st.Config.PendingReboot = reboot.Drop(st.Config.PendingReboot, reboot.SourceTask)
				continue
			}
			st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
				Source: reboot.SourceTask,
				Detail: fmt.Sprintf("task %d (%s)", desired.Task.ID, desired.Task.Type),
				Force:  desired.Task.Force,
				TaskID: desired.Task.ID,
			})
			out.say(fmt.Sprintf("%s: task %d (%s) waiting", capability, desired.Task.ID, desired.Task.Type))
			continue
		case "power":
			// Schedules are kept for the run loop to fire between polls;
			// an on-demand action is a forced request to the coordinator,
			// accepted here and consumed on the server by that report.
			if desired.Power == nil {
				st.Config.PowerSchedules = nil
				continue
			}
			st.Config.PowerSchedules = desired.Power.Schedules
			for _, od := range desired.Power.OnDemand {
				st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
					Source: "power", Detail: fmt.Sprintf("on-demand %s", od.Action), Force: true, Mode: od.Action,
				})
				out.say(fmt.Sprintf("power: on-demand %s accepted", od.Action))
				if _, err := client.Result(ctx, enroll.ResultRequest{
					Revision: desired.Revision, Capability: capability, Status: provider.StatusApplied,
					Detail: fmt.Sprintf("on-demand %s accepted (id %d)", od.Action, od.ID),
				}); err != nil {
					out.say("result: " + err.Error())
					allOK = false
				}
			}
			continue
		case "autologout":
			// Stored, not acted on here. The policy is in minutes and the
			// poll interval is an admin's choice -- five minutes by
			// default and often far more -- so it is evaluated on the
			// session sampler's tick instead (cmd/fog-agent/autologout.go).
			// Nothing to report but the fact that it was accepted: the
			// capability produces a result when it logs somebody off, and
			// an idle-timeout policy that has not fired yet has no outcome.
			was := st.Config.AutoLogout
			if desired.AutoLogout == nil {
				st.Config.AutoLogout = autologout.Policy{}
			} else {
				st.Config.AutoLogout = *desired.AutoLogout
			}
			if was != st.Config.AutoLogout {
				if st.Config.AutoLogout.Enabled() {
					out.say(fmt.Sprintf("autologout: %d minutes idle, %ds warning",
						st.Config.AutoLogout.Minutes, st.Config.AutoLogout.WarnSeconds))
				} else {
					out.say("autologout: off")
				}
			}
			continue
		case "software":
			// The desired package set, converged in order. Outcomes do
			// not hold the revision: a failed install is reported and
			// tried again at the drift check, not every poll. Only a
			// report that did not land keeps the revision unapplied.
			if desired.Software == nil {
				st.Config.SoftwareDrift = 0
				continue
			}
			st.Config.SoftwareDrift = desired.Software.DriftInterval
			if !runSoftware(ctx, st, client, desired.Revision, desired.Software, out) {
				allOK = false
			}
			continue
		case "directory":
			// Design 0009 §6: join the machine to the domain the host
			// record asks for. The block is absent for nearly every
			// host -- the server sends it only to one it believes is
			// unjoined -- and absent means there is nothing to do, not
			// that the machine should leave anything.
			if desired.Directory == nil {
				continue
			}
			if !runDirectory(ctx, st, client, desired.Revision, desired.Directory, out) {
				allOK = false
			}
			continue
		case "wake":
			// Design 0011: send a magic packet for a FOG host on this
			// machine's own link, because FOG owns no machine there.
			// The block names hosts and their MACs and NEVER a
			// destination -- the agent broadcasts on its own
			// interfaces, and there is no field in which it could be
			// aimed anywhere else.
			if desired.Wake == nil {
				continue
			}
			if !runWake(ctx, client, desired.Revision, desired.Wake, out) {
				allOK = false
			}
			continue
		case "printers":
			// The assigned print queues, converged and reported one by
			// one. Like software and unlike a snapin, nothing here is a
			// task: the set is read fresh every time and an outcome
			// refreshes a row rather than closing one.
			if desired.Printers == nil {
				st.Config.PrintersManaged = false
				continue
			}
			st.Config.PrintersManaged = desired.Printers.Manage != printerset.ManageOff && desired.Printers.Manage != ""
			if !runPrinters(ctx, st, client, desired.Revision, desired.Printers, out) {
				allOK = false
			}
			continue
		case "snapin":
			// The queue in the server's run order, one at a time. A
			// task that could not be fetched stays open for the next
			// poll; everything else closes with a result. The reboot
			// or shutdown a snapin asks for is a reason for the
			// coordinator, forced the way the legacy client's was.
			if !runSnapins(ctx, st, client, desired.Snapins, out) {
				allOK = false
			}
			continue
		default:
			// A capability this build has no provider for: the server
			// is newer, and that is fine (design 0001 5.1).
			continue
		}
		out.say(fmt.Sprintf("%s: %s (%s)", capability, r.Status, r.Detail))
		if _, err := client.Result(ctx, enroll.ResultRequest{
			Revision: desired.Revision, Capability: capability, Status: r.Status, Detail: r.Detail,
		}); err != nil {
			out.say("result: " + err.Error())
		}
		switch r.Status {
		case provider.StatusFailed:
			allOK = false
		case provider.StatusPendingReboot:
			st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
				Source: capability, Detail: r.Detail, Force: force,
			})
		}
	}
	// Update runs last, on purpose and outside the loop. Everything above
	// it is sequential in this goroutine, so by the time it runs there is
	// no snapin child and no package manager mid-install to be killed by
	// the process going away -- which is why Busy is nil rather than a
	// lock nothing else takes.
	//
	// It runs whether or not a provider failed above: a broken print
	// queue must not be able to hold up a security update.
	if desired.Update != nil && has(desired.Capabilities, "update") {
		if len(st.Config.PendingReboot) > 0 {
			// Yield. The machine is going down anyway and the agent
			// comes back with it; doing both means two restarts and a
			// window where a half-applied update meets a reboot.
			out.say("update: deferred, a reboot is pending")
		} else {
			cfg := updateConfig(st)
			cfg.Payload = updatePayload(client)
			r, restart := update.Run(ctx, *desired.Update, cfg)
			out.say(fmt.Sprintf("update: %s (%s)", r.Status, r.Detail))
			if _, err := client.Result(ctx, enroll.ResultRequest{
				Revision: desired.Revision, Capability: "update", Status: r.Status, Detail: r.Detail,
			}); err != nil {
				out.say("result: " + err.Error())
			}
			if restart {
				// Save first. Exiting here skips the bottom of this
				// function, and a pending reboot reason recorded above
				// would otherwise be lost across the restart.
				if err := st.SaveConfig(); err != nil {
					out.say("state: " + err.Error())
				}
				return errUpdated
			}
			if r.Status == provider.StatusFailed {
				allOK = false
			}
		}
	}
	if !allOK {
		// Keep whatever reasons were recorded; only the revision waits.
		_ = st.SaveConfig()
		return errors.New("a provider failed; will retry next poll")
	}
	st.Config.AppliedRevision = desired.Revision
	st.Config.AppliedWith = supportedCapabilities
	return st.SaveConfig()
}

// supportedCapabilities names what this build's reconcile handles, in the
// order of its switch. It is stored next to the applied revision so an
// upgrade that learns a capability re-runs the revision it inherited:
// the Windows lab upgrade to the power build sat on an on-demand shutdown
// for ten minutes because the old binary had already marked that revision
// applied, and nothing moved it until an unrelated task did.
const supportedCapabilities = "hostname,taskreboot,power,software,printers,directory,wake,snapin,autologout,update"

// needsReconcile says whether the server's revision must be converged: it
// is not the one applied, or it was applied by a build that handled a
// different set of capabilities.
func needsReconcile(cfg enroll.Config, revision string) bool {
	return revision != cfg.AppliedRevision || cfg.AppliedWith != supportedCapabilities
}

// runSnapins runs the queue in order and reports each task. It returns
// false when a task is left open (a fetch failed) or a report did not
// land, so the revision stays unapplied and the next poll comes back.
func runSnapins(ctx context.Context, st *enroll.State, client *enroll.Client, queue []snapin.Task, out *sayer) bool {
	dir := filepath.Join(st.Dir, "snapins")
	for _, t := range queue {
		r := snapin.Run(ctx, t, dir, func(ctx context.Context, w io.Writer) error {
			return client.Payload(ctx, "snapin", t.ID, w)
		})
		if !r.Fetched {
			out.say(fmt.Sprintf("snapin %q (task %d): %s; will retry next poll", t.Name, t.ID, r.Details))
			return false
		}
		outcome, err := client.Result(ctx, enroll.ResultRequest{
			Revision: st.Config.AppliedRevision, Capability: "snapin", Status: provider.StatusApplied,
			Item: &enroll.ResultItem{ID: t.ID, Status: r.Status, ExitCode: r.ExitCode, Details: r.Details},
		})
		if err != nil {
			out.say("snapin result: " + err.Error())
			return false
		}
		out.say(fmt.Sprintf("snapin %q (task %d): %s, exit %d, outcome %s (%s)", t.Name, t.ID, r.Status, r.ExitCode, outcome, firstLine(r.Details)))
		// The server read the exit code against the snapin's return-code
		// table; the agent acts on its answer, not on the number.
		switch outcome {
		case enroll.OutcomeRetry:
			// The task went back to queued (an installer was busy, say).
			// Stop here so the revision stays unapplied and the next poll
			// starts the queue again from this task.
			out.say("snapin: retry later; stopping the queue for this poll")
			return false
		case enroll.OutcomeReboot:
			st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
				Source: "snapin", Detail: fmt.Sprintf("snapin %q asked for a reboot (exit %d)", t.Name, r.ExitCode), Force: true, Mode: reboot.ModeReboot,
			})
		case enroll.OutcomeFailed:
			if t.AbortOnFail {
				out.say("snapin: job aborts on failure; leaving the rest to the server")
				return true
			}
		}
		if t.Action != "" {
			st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
				Source: "snapin", Detail: fmt.Sprintf("snapin %q", t.Name), Force: true, Mode: t.Action,
			})
		}
	}
	return true
}

// runSoftware converges the software set and reports every entry. It
// returns false only when a report did not land.
func runSoftware(ctx context.Context, st *enroll.State, client *enroll.Client, revision string, policy *software.Policy, out *sayer) bool {
	backend := &software.Choco{}
	bootstrapFailed := false
	if ok, _ := backend.Available(); !ok && policy.Bootstrap.URL != "" {
		// The backend is missing and the server says to install it.
		// Reported as a result on the capability, so the audit says
		// where Chocolatey came from; the entries then run as usual.
		out.say("software: Chocolatey is missing; bootstrapping from " + policy.Bootstrap.URL)
		bctx, cancel := context.WithTimeout(ctx, software.BootstrapTimeout)
		tail, err := software.InstallChoco(bctx, software.BootstrapClient(st.CA()), policy.Bootstrap, st.Dir)
		cancel()
		status, detail := provider.StatusApplied, "Chocolatey bootstrap: installed from "+policy.Bootstrap.URL
		if err != nil {
			bootstrapFailed = true
			status, detail = provider.StatusFailed, "Chocolatey bootstrap failed: "+err.Error()+"\n"+tail
		}
		out.say(firstLine(detail))
		if _, err := client.Result(ctx, enroll.ResultRequest{Revision: revision, Capability: "software", Status: status, Detail: detail}); err != nil {
			out.say("result: " + err.Error())
		}
	}
	reports := software.Converge(ctx, backend, policy.Entries)
	ok := true
	for _, r := range reports {
		outcome, err := client.Result(ctx, enroll.ResultRequest{
			Revision: revision, Capability: "software", Status: provider.StatusApplied,
			Item: &enroll.ResultItem{ID: r.Entry.ID, Status: r.Status, ExitCode: r.ExitCode, InstalledVersion: r.InstalledVersion, Details: r.Details},
		})
		if err != nil {
			out.say(fmt.Sprintf("software %q: %s", r.Entry.Package, err))
			ok = false
			continue
		}
		out.say(fmt.Sprintf("software %q: %s, exit %d, outcome %s, installed %q (%s)", r.Entry.Package, r.Status, r.ExitCode, outcome, r.InstalledVersion, firstLine(r.Details)))
		if outcome == enroll.OutcomeReboot {
			// Not forced: an installer that wants a reboot to finish can
			// wait for the logged-in user, unlike a task or a snapin.
			st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
				Source: "software", Detail: fmt.Sprintf("%s asked for a reboot (exit %d)", r.Entry.Package, r.ExitCode), Mode: reboot.ModeReboot,
			})
		}
	}
	st.Config.SoftwareChecked = time.Now()
	// A set the backend could not run at all is reported once, and the
	// binary is then looked for every poll: installing Chocolatey is the
	// admin's next move, and six hours is the wrong wait for it.
	st.Config.SoftwareBlocked = len(reports) > 0
	for _, r := range reports {
		if r.Status != software.StatusCannotRun {
			st.Config.SoftwareBlocked = false
		}
	}
	if bootstrapFailed {
		// Not every poll: a bootstrap that failed is tried again at the
		// drift check, like any other failed action.
		st.Config.SoftwareBlocked = false
	}
	return ok
}

// runPrinters converges the assigned print queues and reports every one of
// them, including the ones that needed nothing. It returns false only when a
// report did not land.
//
// The two ways nothing can be attempted are reported rather than swallowed:
// no lpadmin, and an installed set that could not be read. The second is the
// one worth spelling out -- converging against an unknown installed set would
// decide "not installed" for every printer and run lpadmin against the whole
// estate every poll, which is the hot loop this design keeps avoiding.
func runPrinters(ctx context.Context, st *enroll.State, client *enroll.Client, revision string, policy *printerset.Policy, out *sayer) bool {
	if !st.Config.PrintersManaged {
		return true
	}
	backend := printerset.Native()
	var reports []printerset.Report
	switch observed, read := printers.Gather(); {
	case !read:
		reports = printerset.Unsupported(*policy, "the installed printers could not be read; nothing was changed")
	default:
		if ok, why := backend.Available(); !ok {
			reports = printerset.Unsupported(*policy, why)
			break
		}
		reports = printerset.Converge(ctx, backend, *policy, observed)
	}

	ok := true
	for _, r := range reports {
		outcome, err := client.Result(ctx, enroll.ResultRequest{
			Revision: revision, Capability: "printers", Status: provider.StatusApplied,
			Item: &enroll.ResultItem{ID: r.Printer.ID, Status: r.Status, Details: r.Error},
		})
		if err != nil {
			out.say(fmt.Sprintf("printer %q: %s", r.Printer.Name, err))
			ok = false
			continue
		}
		// The provider's own words when there are any: a printer that
		// would not install is the whole reason this capability exists,
		// and the reason it did not is the useful half of the line.
		why := r.Detail
		if r.Error != "" {
			why = r.Error
		}
		out.say(fmt.Sprintf("printer %q: %s, outcome %s (%s)", r.Printer.Name, r.Status, outcome, firstLine(why)))
	}
	st.Config.PrintersChecked = time.Now()
	return ok
}

// runWake broadcasts a magic packet for each FOG host the server named,
// and reports what went out.
//
// Nothing here is stateful and nothing is a task: the block is a list of
// wakes pending right now, and an outcome closes the server's request
// rather than moving a revision. An agent that fails to relay has cost the
// wake nothing that the current path -- fire and forget from a node that
// cannot reach the link at all -- was not already costing it.
func runWake(ctx context.Context, client *enroll.Client, revision string, policy *wake.Policy, out *sayer) bool {
	sender, err := wake.NewUDPSender(ctx)
	if err != nil {
		out.say("wake: " + err.Error())
		return false
	}
	defer sender.Close()

	ok := true
	for _, r := range wake.Run(sender, *policy) {
		outcome, err := client.Result(ctx, enroll.ResultRequest{
			Revision: revision, Capability: "wake", Status: provider.StatusApplied,
			Item: &enroll.ResultItem{ID: r.Target.ID, Status: r.Status,
				Packets: r.Packets, Details: r.Detail},
		})
		if err != nil {
			out.say(fmt.Sprintf("wake host %d: %s", r.Target.ID, err))
			ok = false
			continue
		}
		why := r.Detail
		if r.Error != "" {
			why = r.Error
		}
		out.say(fmt.Sprintf("wake host %d: %s, outcome %s (%s)",
			r.Target.ID, r.Status, outcome, firstLine(why)))
	}

	return ok
}

// runDirectory joins the machine to its domain if it should be, and reports
// what happened either way. It returns false only when the report did not
// land.
//
// The credential never reaches this function's log line, its state file or
// its error path: it lives inside a secret.Secret, which redacts itself
// under every printer and marshaler in the process, and Converge zeroes it
// on the way out.
func runDirectory(ctx context.Context, st *enroll.State, client *enroll.Client, revision string, policy *directoryjoin.Policy, out *sayer) bool {
	observed, read := directory.Gather()
	if !read {
		// Nothing is known about this machine's membership, so nothing can
		// be decided about it -- and a join attempted on no information is
		// a join attempted against a machine that may already be in the
		// domain. Reported so it is visible rather than silent.
		observed = directory.Directory{}
		out.say("directory: this platform cannot report its membership; not joining")
		r := directoryjoin.Report{Status: directoryjoin.StatusUnsupported,
			Error: "the machine's directory membership could not be read; nothing was attempted"}
		return reportDirectory(ctx, st, client, revision, r, out)
	}

	current, _ := hostname.Current()
	names := directoryjoin.Names{Current: current, Pending: hostname.Pending()}
	r := directoryjoin.Converge(ctx, directoryjoin.Native(), policy, observed, names)
	return reportDirectory(ctx, st, client, revision, r, out)
}

// reportDirectory sends one join outcome and acts on the reboot it asks for.
func reportDirectory(ctx context.Context, st *enroll.State, client *enroll.Client, revision string, r directoryjoin.Report, out *sayer) bool {
	why := r.Detail
	if r.Error != "" {
		why = r.Error
	}
	out.say(fmt.Sprintf("directory: %s (%s)", r.Status, firstLine(why)))
	// An ITEM report, addressed by this agent's own host id: the join's
	// status vocabulary (joined, refused, unsupported) does not fit in the
	// capability's applied/failed, and `failed` would mean two different
	// things in one field.
	if _, err := client.Result(ctx, enroll.ResultRequest{
		Revision: revision, Capability: "directory", Status: provider.StatusApplied,
		Item: &enroll.ResultItem{ID: st.Config.HostID, Status: r.Status, Details: r.Error},
	}); err != nil {
		out.say("directory result: " + err.Error())
		return false
	}
	// The machine just changed its own membership, so the facts this agent
	// last sent are stale by its own doing. Marking them due re-collects on
	// the next poll instead of waiting out FactsInterval.
	//
	// Not a tidy-up. The server decides whether to send the join credential
	// from the FACT, not from this result, and it cannot ask for a refresh
	// -- `want_directory` is true only while it has no hash at all. So
	// without this the server can believe a freshly joined host unjoined
	// for up to an hour, and DirectoryJoin's own cooldown is exactly an
	// hour: the two line up, and the credential goes out once more to a
	// machine that is already in the domain. Measured on the Windows lab
	// host 2026-09-04, where the join landed moments after that poll's
	// facts had been gathered and the polls after it reported nothing.
	//
	// FactsChecked and not DirectoryHash: the hash is compared only AFTER
	// factsDue has already let the collection run, so clearing it changes
	// nothing on its own -- and the hash will differ anyway, because the
	// membership did. Re-collecting the other facts once after a join is
	// the price, and a join is rare.
	if r.Status == directoryjoin.StatusJoined ||
		r.Status == directoryjoin.StatusAlreadyJoined ||
		r.Status == directoryjoin.StatusRenamed {
		st.Config.FactsChecked = time.Time{}
	}
	if r.Reboot {
		// Forced when the host's "Enforce Hostname | AD Join Reboots" flag
		// is set (protocol-v1, the reboot coordinator): a logged-in user
		// gets FOG_GRACE_TIMEOUT of warning, then the restart. Unset, it
		// waits for every user to leave.
		st.Config.PendingReboot = reboot.Merge(st.Config.PendingReboot, reboot.Reason{
			Source: "directory", Detail: "joined a domain; a restart finishes it",
			Force: r.Force, Mode: reboot.ModeReboot,
		})
	}
	return true
}

// printersDriftDue says whether the assigned printers should be re-converged
// without the revision having moved. FactsInterval, because that is the
// cadence at which the agent looks at the printer set anyway.
func printersDriftDue(cfg enroll.Config, now time.Time) bool {
	return cfg.PrintersManaged && now.Sub(cfg.PrintersChecked) >= FactsInterval
}

// blockedCleared says whether a backend that was missing at the last run
// is there now; a stat, so it costs nothing per poll.
func blockedCleared(st *enroll.State) bool {
	if !st.Config.SoftwareBlocked {
		return false
	}
	ok, _ := (&software.Choco{}).Available()
	return ok
}

// driftDue says whether the software set should be re-checked without
// the revision having moved.
func driftDue(st *enroll.State, policy *software.Policy, now time.Time) bool {
	if policy == nil || len(policy.Entries) == 0 || policy.DriftInterval <= 0 {
		return false
	}
	return now.Sub(st.Config.SoftwareChecked) >= time.Duration(policy.DriftInterval)*time.Second || blockedCleared(st)
}

// firstLine is enough of a detail for the console; the server has the rest.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// driftMayBeDue is the cheap half of the drift decision, made before the
// poll so the state can be asked for: the interval the last reconcile
// saw has passed, a blocked set may have become runnable, or the printers
// are due another look.
func driftMayBeDue(st *enroll.State) bool {
	return softwareDriftMayBeDue(st) || printersDriftDue(st.Config, time.Now())
}

// softwareDriftMayBeDue is that decision for the software set alone.
func softwareDriftMayBeDue(st *enroll.State) bool {
	return st.Config.SoftwareDrift > 0 && (time.Since(st.Config.SoftwareChecked) >= time.Duration(st.Config.SoftwareDrift)*time.Second || blockedCleared(st))
}

// drift converges the parts of a state whose revision has not moved,
// leaving the applied revision alone. Each subsystem decides for itself
// whether it is due; the poll asked for the state because at least one was.
func drift(ctx context.Context, st *enroll.State, client *enroll.Client, desired *enroll.DesiredState, out *sayer) error {
	if driftDue(st, desired.Software, time.Now()) {
		runSoftware(ctx, st, client, desired.Revision, desired.Software, out)
	}
	if desired.Printers != nil && printersDriftDue(st.Config, time.Now()) {
		runPrinters(ctx, st, client, desired.Revision, desired.Printers, out)
	}
	return st.SaveConfig()
}

// coordinate is the reboot coordinator's turn: with reasons outstanding it
// looks at who is logged in, applies the policy, reports the decision as
// a result, and reboots when allowed. It is the only caller of
// reboot.Execute in the agent.
func coordinate(ctx context.Context, st *enroll.State, client *enroll.Client, out *sayer) error {
	return coordinateForPlatform(ctx, st, client, out, runtime.GOOS == "windows")
}

var rebootUsers = reboot.LoggedIn
var requestReboot = reboot.Execute

func coordinateForPlatform(ctx context.Context, st *enroll.State, client *enroll.Client, out *sayer, windows bool) error {
	if len(st.Config.PendingReboot) == 0 {
		return nil
	}
	pending := st.Config.PendingReboot
	var rejoinWithheld []reboot.Reason
	var attempt *directoryjoin.Attempt
	var rejoinRebootClaimed bool
	if windows {
		var markerErr error
		attempt, markerErr = directoryjoin.LoadAttempt(st.Dir)
		pending = nil
		for _, reason := range st.Config.PendingReboot {
			// A completed/archived operation cannot authorize another reboot.
			// Only an unrequested awaiting_reboot latch can be acquired below.
			if reason.Source == "directory-rejoin" && (markerErr != nil || attempt == nil || attempt.Phase != "awaiting_reboot" || attempt.RebootRequested) {
				continue
			}
			if reason.Source == reboot.SourceTask && (markerErr != nil || (attempt != nil && attempt.Phase != "verified")) {
				rejoinWithheld = append(rejoinWithheld, reason)
			} else {
				pending = append(pending, reason)
			}
		}
	}
	users, err := rebootUsers()
	if err != nil {
		return err
	}

	// A task reason means the machine has to come back in FOS, and it
	// reaches FOS by booting from the network (design 0013). If the
	// firmware cannot be pointed there, rebooting for that task takes the
	// machine away from whoever is using it and changes nothing: the task
	// is still queued when it comes back, so the next poll asks again and
	// the machine reboots on a loop.
	//
	// So the task reason is withheld rather than acted on. It stays
	// pending -- an admin may yet enable PXE in firmware setup -- and any
	// OTHER reason still gets its reboot, because a machine must not be
	// held hostage by a task it cannot serve.
	var armTo netboot.Option
	arming := false
	var findErr error
	if hasTaskReason(pending) {
		armTo, findErr = findNetboot()
		arming = findErr == nil
	}
	reasons, withheld, refusal := planReboot(pending, findErr)
	withheld = append(withheld, rejoinWithheld...)
	if len(rejoinWithheld) > 0 && len(reasons) == 0 {
		refusal = "directory rejoin verification holds imaging"
	}
	if refusal != "" {
		out.say("netboot: " + refusal)
	} else if findErr != nil && hasTaskReason(st.Config.PendingReboot) {
		// Not armed, but not held back either. Said out loud because an
		// unarmed task reboot is otherwise indistinguishable in the log
		// from an armed one.
		out.say("netboot: " + netbootNote(findErr))
	}

	if len(reasons) == 0 {
		// Every reason was withheld. Report the refusal so the task shows
		// why it is not moving, and leave the reasons pending.
		if _, err := client.Result(ctx, enroll.ResultRequest{
			Revision: st.Config.AppliedRevision, Capability: "reboot",
			Status: provider.StatusFailed, Detail: refusal,
		}); err != nil {
			out.say("result: " + err.Error())
		}
		st.Config.PendingReboot = withheld
		return st.SaveConfig()
	}

	d := reboot.Decide(reasons, users, reboot.Policy{Grace: st.Config.RebootGrace})
	status := provider.StatusPendingReboot
	if d.Reboot {
		status = provider.StatusApplied
	}
	detail := d.Why
	if refusal != "" {
		detail += "; task reboot withheld: " + refusal
	}
	out.say(fmt.Sprintf("reboot: %s (%s%s)", status, detail, map[bool]string{true: ", mode " + d.Mode, false: ""}[d.Reboot]))
	if _, err := client.Result(ctx, enroll.ResultRequest{
		Revision: st.Config.AppliedRevision, Capability: "reboot", Status: status, Detail: detail,
	}); err != nil {
		out.say("result: " + err.Error())
	}
	if !d.Reboot {
		return nil
	}
	// Persist before asking: the reboot is asynchronous and the reasons
	// are satisfied the moment it is accepted. A refused request puts
	// them back.
	if attempt != nil && !attempt.RebootRequested {
		for _, reason := range reasons {
			if reason.Source == "directory-rejoin" {
				if e := directoryjoin.SetAttemptRebootRequested(st.Dir, attempt, true); e != nil {
					return e
				}
				attempt.RebootRequested = true
				rejoinRebootClaimed = true
				break
			}
		}
	}
	for _, r := range reasons {
		if r.TaskID != 0 {
			st.Config.RebootedForTask = r.TaskID
		}
	}
	st.Config.PendingReboot = withheld
	// A reboot finishes a rename or a join, so the facts gathered before it
	// are about to be stale. Collect on the first poll after the boot, not
	// an hour later: the server decides whether to send a rename's
	// credential from the reported machine account (design 0017 section
	// 3.2), and an hour of the old account is an hour of a second rename.
	st.Config.FactsChecked = time.Time{}
	if err := st.SaveConfig(); err != nil {
		_ = refusedDirectoryReboot(st, attempt, rejoinRebootClaimed)
		return err
	}
	// Armed as late as possible, and undone if the reboot does not happen:
	// a BootNext left set by a reboot that was refused would send the
	// machine to the network on whatever boot came next, for whatever
	// reason, which is a surprise nobody asked for.
	if arming {
		if err := netboot.Arm(armTo); err != nil {
			if e := refusedDirectoryReboot(st, attempt, rejoinRebootClaimed); e != nil {
				return e
			}
			st.Config.PendingReboot = append(withheld, reasons...)
			st.Config.RebootedForTask = 0
			_ = st.SaveConfig()
			return fmt.Errorf("arming a network boot: %w", err)
		}
		out.say("netboot: armed " + armTo.String() + " for one boot")
	}
	if err := requestReboot(d.Mode, d.Delay, "FOG: "+d.Mode+" for "+d.Why); err != nil {
		if e := refusedDirectoryReboot(st, attempt, rejoinRebootClaimed); e != nil {
			return e
		}
		if arming {
			if derr := netboot.Disarm(); derr != nil {
				out.say("netboot: could not disarm after a failed reboot: " + derr.Error())
			}
		}
		st.Config.PendingReboot = append(withheld, reasons...)
		st.Config.RebootedForTask = 0
		_ = st.SaveConfig()
		return err
	}
	return nil
}

// Execute returns an error only for a refused request (in-progress is success).
// A crash with an uncertain request keeps the latch; a known refusal may retry.
func refusedDirectoryReboot(st *enroll.State, attempt *directoryjoin.Attempt, claimed bool) error {
	if !claimed || attempt == nil || !attempt.RebootRequested {
		return nil
	}
	if err := directoryjoin.SetAttemptRebootRequested(st.Dir, attempt, false); err != nil {
		return err
	}
	attempt.RebootRequested = false
	return nil
}

// findNetboot is netboot.Find, swappable so the withholding policy can be
// tested without firmware.
var findNetboot = netboot.Find

// planReboot splits the pending reasons into the ones to act on now and the
// ones to hold back, given whether a network boot could be armed (design
// 0013 section 3).
//
// findErr nil means armable, or that no task reason was present and the
// question never arose -- both are "nothing to withhold". A non-nil findErr
// withholds every task reason and returns the sentence explaining why. It
// is deliberately only the TASK reasons that are held: a hostname change or
// a software install wants the machine back in its own OS, which a plain
// reboot delivers, so those are unaffected by there being nowhere to
// netboot to.
func planReboot(pending []reboot.Reason, findErr error) (act, withheld []reboot.Reason, refusal string) {
	if findErr == nil || !withholdsTask(findErr) {
		return pending, nil, ""
	}
	for _, r := range pending {
		if r.Source == reboot.SourceTask {
			withheld = append(withheld, r)
		}
	}
	if len(withheld) == 0 {
		return pending, nil, ""
	}
	return reboot.Drop(pending, reboot.SourceTask), withheld, netbootRefusal(findErr)
}

// hasTaskReason reports whether a FOG task is among the reasons: the one
// kind of reboot that has to land somewhere other than the local disk.
func hasTaskReason(reasons []reboot.Reason) bool {
	for _, r := range reasons {
		if r.Source == reboot.SourceTask {
			return true
		}
	}
	return false
}

// withholdsTask reports whether a Find() failure is positive evidence that
// a reboot cannot reach the task.
//
// ONLY ErrNoOption is. It is a fact about the machine: the firmware has a
// boot manager, and that boot manager holds no network entry. A reboot
// provably lands on the local disk, so it must not happen.
//
// ErrUnsupported is not a fact about where the machine will boot, only that
// there is no boot manager to ask -- a BIOS/CSM machine, which is how most
// of FOG's fleet has always reached FOS: by a firmware boot order set to
// network-first that the agent cannot see and never could. Withholding
// there would strand machines that image perfectly today in order to
// prevent a reboot that in all likelihood works. That is a worse failure
// than the one design 0013 set out to fix, and it is the behavior change
// section 7 of that document promised not to make.
//
// Any other error is a failed measurement rather than a finding -- a
// malformed BootOrder, an unreadable variable -- and gets the same benefit
// of the doubt, because "I could not look" is not "there is nothing there".
func withholdsTask(err error) bool {
	return errors.Is(err, netboot.ErrNoOption)
}

// netbootRefusal is the sentence an admin reads on a task that is being
// held back. Only withholdsTask failures reach it.
func netbootRefusal(err error) string {
	if errors.Is(err, netboot.ErrNoOption) {
		return "the firmware lists no network boot entry to arm; enable PXE or network boot in firmware setup"
	}
	return "could not arm a network boot: " + err.Error()
}

// netbootNote is the sentence for a failure that does NOT hold the task
// back. The reboot is going ahead unarmed and will land wherever the
// firmware's own boot order sends it, so saying nothing would make a task
// that quietly did not run look like one that never tried.
func netbootNote(err error) string {
	if errors.Is(err, netboot.ErrUnsupported) {
		return "no UEFI boot manager here, so there is nothing to arm; the task reboot relies on this machine's firmware boot order reaching the network, as it always has"
	}
	return "could not look for a network boot entry (" + err.Error() + "); rebooting unarmed"
}

// cmdRenew renews now, regardless of expiry: an operator's rotation, and
// the way a lab proves the route without waiting out the lead time.
func cmdRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	dir := fs.String("dir", enroll.DefaultDir, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := enroll.Load(*dir)
	if err != nil {
		return err
	}
	if len(st.Cert) == 0 {
		return errors.New("not enrolled: nothing to renew")
	}
	if st.Config.ServerURL == "" || !st.HasTrust() {
		return errors.New("no server or certificate trust remembered; enroll first")
	}
	client, err := st.Client()
	if err != nil {
		return err
	}
	if err := client.UseCertificate(st.Cert, st.Key); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if e := client.RequireDirectoryFeatures(context.Background()); e != nil {
			return e
		}
		a, e := client.CheckIdentity(context.Background(), readIdentity())
		if e != nil {
			return e
		}
		if a.Identity.Status != "matched" {
			return errors.New("identity mismatch: renewal stopped")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	out := &sayer{}
	if err := renew(ctx, st, client, out); err != nil {
		return err
	}
	return printJSON(map[string]any{"host_id": st.Config.HostID, "enrolled": true})
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir := fs.String("dir", enroll.DefaultDir, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := enroll.Load(*dir)
	if err != nil {
		return err
	}
	out := map[string]any{
		"state_dir": st.Dir,
		"server":    st.Config.ServerURL,
		"host_id":   st.Config.HostID,
		"has_key":   st.Key != nil,
		"enrolled":  len(st.Cert) > 0,
	}
	if st.Identity != nil {
		out["key_identity"] = st.Identity.Identity
	}
	return printJSON(out)
}

// askMissing fills in what the command line did not say, when there is a
// person there to be asked. `fog-agent service install` typed at an
// administrator prompt used to answer "--server is required the first
// time" and leave the reader to go and find the flags; the MSI's wizard
// covers a double-click install, and this covers the binary.
//
// Nothing is asked unless stdin is a console -- under msiexec, a
// deployment script or the service itself nobody can answer and the error
// is the right answer -- and nothing is asked once the state directory
// remembers a server, which is the reinstall and the upgrade.
func askMissing(f commonFlags) {
	if !stdinIsConsole() {
		return
	}
	// A named server means somebody is scripting this, and a script that
	// gets asked a question hangs. Only the bare "fog-agent service
	// install" is treated as an invitation to ask; anything with --server
	// on it gets errors, or the certificate confirmation in acquireCA,
	// which is a decision and not a convenience.
	if *f.server != "" {
		return
	}
	st, err := enroll.Load(*f.dir)
	if err != nil || st.Config.ServerURL != "" || st.HasTrust() {
		return
	}
	if *f.server == "" {
		*f.server = ask("FOG server address, the web UI address ending in /fog",
			"https://fog.example.org/fog")
	}
	if *f.token == "" {
		*f.token = ask("Enrollment token, or empty to approve this machine by hand in Host Management", "")
	}
}

// stdinReader is kept across prompts: a fresh bufio.Reader each time would
// discard whatever the last one had already buffered.
var stdinReader = bufio.NewReader(os.Stdin)

// ask puts one question on the terminal. Prompts go to stderr, not through
// logOut, which setup has already pointed at the log file as well.
func ask(label, example string) string {
	fmt.Fprintf(os.Stderr, "\n%s\n", label)
	if example != "" {
		fmt.Fprintf(os.Stderr, "  example: %s\n", example)
	}
	fmt.Fprint(os.Stderr, "> ")
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

// stdinIsConsole reports whether somebody is there typing. A character
// device is the portable test: a pipe, a redirected file and the service's
// null handle are all something else, on Windows as well as on Linux.
func stdinIsConsole() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// cmdSetup prepares the state directory for a service that something else
// registers and starts: the MSI on Windows, a package's unit elsewhere. It
// is the install-time half of `service install` without the service
// control manager half.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	f := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Under msiexec there is no console, so what setup says goes to the
	// service log as well, where the person reading an install failure
	// will look.
	if lf, err := setupLog(*f.dir); err == nil && lf != nil {
		defer lf.Close()
		logOut = io.MultiWriter(logOut, lf)
	}
	out := &sayer{}
	if _, err := prepareState(f, out); err != nil {
		return err
	}
	return postSetup()
}

// prepareState settles the state directory: server and CA remembered, the
// directory locked down before a key is written into it, and one
// enrollment attempt. A server that does not answer is not an error here.
// The token is kept for the service's first attempt instead, so an install
// run by a deployment tool does not fail on a network blip and does not
// lose the token. A fresh directory with no server or CA is an error.
func prepareState(f commonFlags, out *sayer) (*enroll.State, error) {
	askMissing(f)
	st, err := openState(f)
	if err != nil {
		return nil, err
	}
	if err := restrictStateDir(*f.dir); err != nil {
		return nil, err
	}
	if len(st.Cert) > 0 {
		out.say(fmt.Sprintf("already enrolled as host %d", st.Config.HostID))
		return st, nil
	}
	if *f.token != "" {
		st.Config.PendingToken = *f.token
		if err := st.SaveConfig(); err != nil {
			return nil, err
		}
	}
	client, err := st.Client()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "windows" {
		if err = prepareDirectoryIdentity(context.Background(), st, client); err != nil {
			if errors.Is(err, enroll.ErrDirectoryFeaturesUnavailable) {
				out.say("directory feature check unavailable; service staged without enrollment")
				return st, nil
			}
			return nil, err
		}
	}
	req, err := enrollRequest(st, st.Config.PendingToken, out)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	resp, err := enrollLoop(ctx, st, client, req, true, out)
	cancel()
	switch {
	case err != nil:
		out.say("the server did not answer; the service will keep trying")
	case resp.Status == enroll.StatusPending:
		out.say("the service will keep asking until an admin approves this host in Host Management")
	}
	return st, nil
}
