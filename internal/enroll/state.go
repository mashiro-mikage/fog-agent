// Package enroll owns the agent's local identity material: the private key,
// the SMBIOS identity it was generated for, and the certificate the server
// issued. It also performs the enrollment request (docs/design/protocol-v1.md).
package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/provider/autologout"
	"github.com/FOGProject/fog-agent/internal/provider/directoryjoin"
	"github.com/FOGProject/fog-agent/internal/provider/power"
	"github.com/FOGProject/fog-agent/internal/reboot"
	"github.com/FOGProject/fog-agent/internal/usersession"
)

// Files inside the state directory.
const (
	keyFile      = "key.pem"       // EC P-256 private key, 0600
	identityFile = "identity.json" // SMBIOS identity the key was generated for
	certFile     = "cert.pem"      // issued certificate, empty until enrolled
	caFile       = "ca.pem"        // CA bundle the agent trusts for its server
	configFile   = "config.json"   // server URL and host id
)

// Config is the small amount of local configuration; everything else comes
// from the server (design doc 10.3).
type Config struct {
	ServerURL string `json:"server_url"`
	// SystemTrust means the server is verified against this machine's trust
	// store and its name instead of a pinned CA: its certificate is not
	// issued by the CA it publishes, and the machine already trusted it
	// when the agent was set up (design 0002). Only that probe sets it; a
	// CA file clears it.
	SystemTrust bool `json:"system_trust,omitempty"`
	HostID      int  `json:"host_id,omitempty"`
	// AppliedRevision is the desired-state revision every capability last
	// converged on without failing; a poll reporting a different one is
	// what triggers a fetch. Empty until the first reconcile.
	// PendingToken is an enrollment token setup kept for the service's
	// first attempt, when the server did not answer at install time.
	// Cleared once a certificate is issued.
	PendingToken string `json:"pending_token,omitempty"`

	AppliedRevision string `json:"applied_revision,omitempty"`
	// AppliedWith is the capability list of the build that applied it; a
	// build with a different list treats the revision as unapplied.
	AppliedWith string `json:"applied_with,omitempty"`
	// PendingReboot is what the reboot coordinator still owes: reasons
	// recorded by providers and the task poll that policy has not yet
	// let it act on. Persisted so a restart does not forget them.
	PendingReboot []reboot.Reason `json:"pending_reboot,omitempty"`
	// RebootGrace is the server's FOG_GRACE_TIMEOUT as of the last
	// reconcile, kept so a deferred reboot uses it on a later poll.
	RebootGrace int `json:"reboot_grace,omitempty"`
	// RebootedForTask is the FOG task this agent last rebooted for. A
	// machine that came back with the same task still queued did not
	// boot into FOS, and rebooting it again every poll fixes nothing;
	// a new task (a new id) is a new request.
	RebootedForTask int `json:"rebooted_for_task,omitempty"`
	// SoftwareChecked is when the software set was last converged. The
	// drift check re-runs it after the server's interval even when the
	// revision has not moved.
	SoftwareChecked time.Time `json:"software_checked,omitzero"`
	// SoftwareDrift is the server's drift interval in seconds as of the
	// last reconcile; zero when the host has no software set.
	SoftwareDrift int `json:"software_drift,omitempty"`
	// SoftwareBlocked is set when the last run could not run its backend
	// at all (Chocolatey missing); the binary is then looked for every
	// poll so installing it converges the host at once.
	SoftwareBlocked bool `json:"software_blocked,omitempty"`
	// PrintersManaged is set when the last reconcile saw a printers mode
	// other than off, and PrintersChecked is when the set was last
	// converged. Together they are the printers drift check: a user who
	// deletes an assigned queue gets it back without an admin having to
	// touch the assignment to move the revision. There is no server-sent
	// interval for this the way software has one -- the cadence is
	// FactsInterval, because looking at the printer set is the same act
	// the facts collector already performs on that schedule.
	PrintersManaged bool      `json:"printers_managed,omitempty"`
	PrintersChecked time.Time `json:"printers_checked,omitzero"`
	// PowerSchedules is the host's resolved shutdown and reboot schedules
	// as of the last reconcile, fired by the run loop between polls.
	PowerSchedules []power.Schedule `json:"power_schedules,omitempty"`
	// PowerFired is the last scheduled firing acted on, kept so a machine
	// that comes back within the same minute does not fire it again.
	PowerFired time.Time `json:"power_fired,omitzero"`
	// InventoryHash and SoftwareHash are the content hashes of the fact
	// blocks the server has accepted (design 0006 §2). The agent sends a
	// block only when the hash it computes now differs from these, and
	// records the new one only after the poll returns 200 -- so a lost
	// poll resends rather than silently dropping the change.
	InventoryHash string `json:"inventory_hash,omitempty"`
	SoftwareHash  string `json:"software_hash,omitempty"`
	// DirectoryHash is the same gate for the directory-membership block
	// (design 0009 §3). Membership changes on the scale of someone joining
	// a machine to a domain, so this hash almost never moves -- which is
	// the point: an unchanged answer costs one comparison, not a row.
	DirectoryHash string `json:"directory_hash,omitempty"`
	// PrintersHash is the same gate for the installed-printers block
	// (design 0010 §3).
	PrintersHash string `json:"printers_hash,omitempty"`
	// NetworkHash is the same gate for the interfaces block (design 0011
	// §3). The one fact gathered on every poll rather than on
	// FactsInterval -- it is a single syscall, and it is what the server
	// picks wake relays from, so staleness costs a wake.
	NetworkHash string `json:"network_hash,omitempty"`
	// SecureBootHash is the same gate for the firmware's Secure Boot
	// posture (design 0012 §3).
	SecureBootHash string `json:"secureboot_hash,omitempty"`
	// FactsChecked is when the collectors last ran. They are re-run on
	// FactsInterval rather than every poll: enumerating a package-managed
	// host's 2800 packages every five minutes buys nothing.
	FactsChecked time.Time `json:"facts_checked,omitzero"`
	// WantInventory and WantSoftware are the server's request from the
	// last poll answer, honored on the next poll regardless of whether
	// anything changed locally.
	WantInventory  bool `json:"want_inventory,omitempty"`
	WantSoftware   bool `json:"want_software,omitempty"`
	WantDirectory  bool `json:"want_directory,omitempty"`
	WantPrinters   bool `json:"want_printers,omitempty"`
	WantNetwork    bool `json:"want_network,omitempty"`
	WantSecureBoot bool `json:"want_secureboot,omitempty"`
	// UnauthorizedSince is when an unbroken run of 401s began that the
	// server did NOT attribute to this agent's certificate. The identity
	// is kept while it runs, and discarded only once it outlasts
	// UnauthorizedGrace -- the backstop for a 401 that never reaches the
	// application and so carries no reason. Cleared by any poll that
	// succeeds.
	UnauthorizedSince time.Time `json:"unauthorized_since,omitzero"`
	// SessionsAcked is the digest of the open user-session set the server
	// last accepted (design 0008 section 4). Sessions do NOT use the facts
	// hash gate: the open set is also the server's evidence a session is
	// still alive, so it is resent on SessionResyncInterval even unchanged.
	SessionsAcked string `json:"sessions_acked,omitempty"`
	// SessionsPending are sessions the agent watched end but the server has
	// not acknowledged. Held here, not dropped, so a failed poll resends the
	// closure rather than losing it -- a lost close becomes a session that
	// stays open forever, which is the legacy defect 0008 exists to fix.
	SessionsPending []usersession.Session `json:"sessions_pending,omitempty"`
	// SessionsChecked is when the open set was last accepted by the server.
	SessionsChecked time.Time `json:"sessions_checked,omitzero"`
	// SessionsDisabled is set when the server said collect_sessions was
	// false, which is FOG's usertracker module turned off for this host. The
	// agent then does not collect at all: the privacy-relevant act is reading
	// who is logged on, not sending it.
	SessionsDisabled bool `json:"sessions_disabled,omitempty"`
	// FactsDisabled is set when the server said collect_facts was false.
	// Stored rather than re-read each poll so a restart does not resume
	// gathering on a site that turned it off.
	FactsDisabled bool `json:"facts_disabled,omitempty"`
	// AutoLogout is the idle-logoff policy the server last sent (design
	// 0014). Persisted for the same reason PowerSchedules is: it is
	// evaluated between polls, so an agent that had to reread it from the
	// server before acting would do nothing for a whole poll interval after
	// every restart.
	AutoLogout autologout.Policy `json:"autologout,omitzero"`
}

// State is the on-disk material. Load never generates anything by itself;
// callers decide when a key should exist.
type State struct {
	DirectoryCheck       *DirectoryCheck
	DirectoryObservation *DirectoryObservation
	DirectoryObservedAt  time.Time
	Dir                  string
	Key                  *ecdsa.PrivateKey
	Identity             *identity.Host // identity recorded at key generation, nil if none
	Cert                 []byte         // PEM, nil until issued
	Config               Config
}

// DirectoryCheck is read-only policy metadata, never a join credential.
type DirectoryCheck struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	DC       string `json:"dc"`
	Revision string `json:"revision"`
}

type DirectoryObservation struct {
	directoryjoin.RejoinObservation
	Revision    string `json:"revision"`
	DC          string `json:"dc"`
	DCReachable bool   `json:"dc_reachable"`
}

// Load reads whatever exists in dir. A missing key is not an error; a key
// that cannot be parsed is.
func Load(dir string) (*State, error) {
	// Created here, not in EnsureKey, so whatever is written first -- the
	// CA bundle, the config, the key -- finds the directory. `run` writes
	// the bundle before it ever touches the key.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &State{Dir: dir}
	if b, err := os.ReadFile(filepath.Join(dir, configFile)); err == nil {
		if err := json.Unmarshal(b, &st.Config); err != nil {
			return nil, fmt.Errorf("enroll: %s: %w", configFile, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, keyFile))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("enroll: %s is not an EC private key", keyFile)
	}
	if st.Key, err = x509.ParseECPrivateKey(blk.Bytes); err != nil {
		return nil, fmt.Errorf("enroll: %s: %w", keyFile, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, identityFile)); err == nil {
		var id identity.Host
		if err := json.Unmarshal(b, &id); err == nil {
			st.Identity = &id
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, certFile)); err == nil && len(b) > 0 {
		st.Cert = b
	}
	return st, nil
}

// EnsureKey returns the existing key if it was generated for the live
// identity, and otherwise generates a fresh one and forgets any certificate.
// This is the clone and reimage guard (design doc 4.4): a captured image
// carries the original machine's key, and the SMBIOS tuple is how the copy
// finds out it is not that machine. The live identity is always recorded so
// the next start compares against what was actually presented.
//
// A new key also resets config.json to how to reach the server. Everything
// else in it -- host id, applied revision, fact hashes, queued reboots and
// session closures -- describes the host record the old key was bound to.
// A clone that kept the hashes would never send its own software list,
// because it matches the one the original machine already sent.
func (st *State) EnsureKey(live identity.Host) (regenerated bool, err error) {
	if st.Key != nil && st.Identity != nil && (sameMachine(*st.Identity, live) || unreadable(live)) {
		return false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(st.Dir, 0o700); err != nil {
		return false, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFile(filepath.Join(st.Dir, keyFile), pemBytes, 0o600); err != nil {
		return false, err
	}
	idBytes, _ := json.Marshal(live)
	if err := writeFile(filepath.Join(st.Dir, identityFile), idBytes, 0o600); err != nil {
		return false, err
	}
	// A new key means any old certificate is for a key we no longer hold.
	_ = os.Remove(filepath.Join(st.Dir, certFile))
	st.Key, st.Identity, st.Cert = key, &live, nil
	st.Config = Config{ServerURL: st.Config.ServerURL, PendingToken: st.Config.PendingToken}
	if err := st.SaveConfig(); err != nil {
		return true, err
	}
	return true, nil
}

// sameMachine compares only the SMBIOS tuple. MACs change with docks and
// USB adapters and must not trigger a re-enroll. Two machines whose tuple is
// entirely empty or the same placeholder (some VMs, some white-box boards)
// compare equal here, so a clone between them keeps the key; nothing on the
// wire separates those, and the image must be captured without the key.
func sameMachine(a, b identity.Host) bool {
	return a.SystemUUID == b.SystemUUID &&
		a.SystemSerial == b.SystemSerial &&
		a.BoardSerial == b.BoardSerial &&
		a.ChassisAsset == b.ChassisAsset
}

// unreadable is a read that returned no identity and said why. That is a
// firmware call that failed, not evidence of another machine. Now the guard
// runs on every start, treating it as a clone would throw away a working
// enrollment and leave the host waiting for an admin. An empty tuple with
// no warning is a real reading and is compared like any other.
func unreadable(h identity.Host) bool {
	return h.SystemUUID == "" && h.SystemSerial == "" && h.BoardSerial == "" &&
		h.ChassisAsset == "" && len(h.Warnings) > 0
}

// CSR builds a certificate request for the key. The subject is a
// placeholder: the server sets the real one on issue (protocol-v1.md).
func (st *State) CSR() ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, st.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SaveIssued stores the certificate and the host id the server assigned.
func (st *State) SaveIssued(certPEM []byte, hostID int) error {
	if err := writeFile(filepath.Join(st.Dir, certFile), certPEM, 0o600); err != nil {
		return err
	}
	st.Cert = certPEM
	st.Config.HostID = hostID
	return st.SaveConfig()
}

// DropIssued forgets the certificate and host id, keeping the key: the
// next enrollment presents the same key, which is what lets the server
// recognize a host it still has ("reissue") or re-pend one it does not.
func (st *State) DropIssued() error {
	if err := os.Remove(filepath.Join(st.Dir, certFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	st.Cert = nil
	st.Config.HostID = 0
	return st.SaveConfig()
}

// SaveConfig writes config.json.
func (st *State) SaveConfig() error {
	b, _ := json.MarshalIndent(st.Config, "", "  ")
	return writeFile(filepath.Join(st.Dir, configFile), b, 0o600)
}

// SaveCA stores the server CA bundle the agent will trust. A pinned bundle
// replaces system trust, so the flag goes with it.
func (st *State) SaveCA(pemBytes []byte) error {
	if err := writeFile(filepath.Join(st.Dir, caFile), pemBytes, 0o600); err != nil {
		return err
	}
	if st.Config.SystemTrust {
		st.Config.SystemTrust = false
		return st.SaveConfig()
	}
	return nil
}

// UseSystemTrust records that the server is verified against this machine's
// trust store and its name, and removes any pinned bundle, so the two can
// never disagree about what is trusted.
func (st *State) UseSystemTrust() error {
	if err := os.Remove(filepath.Join(st.Dir, caFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	st.Config.SystemTrust = true
	return st.SaveConfig()
}

// HasTrust reports whether anything is settled to verify the server with.
func (st *State) HasTrust() bool {
	return st.Config.SystemTrust || len(st.CA()) > 0
}

// Client builds the client for what the state settled: the pinned bundle,
// or this machine's trust store.
func (st *State) Client() (*Client, error) {
	if st.Config.SystemTrust {
		return NewSystemTrustClient(st.Config.ServerURL), nil
	}
	return NewClient(st.Config.ServerURL, st.CA())
}

// ReadCABundle reads a CA file the person installing the agent pointed at
// and returns it as PEM. DER is accepted and converted because the FOG
// server publishes both forms side by side --
// management/other/ca.cert.pem and ca.cert.der -- and a browser saving the
// .der one is an entirely reasonable way to get the file onto a Windows
// machine. Without this the DER lands in the state directory and the only
// symptom is "CA bundle contains no certificates" from NewClient, which
// says nothing about the format.
func ReadCABundle(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		return raw, nil
	}
	certs, err := x509.ParseCertificates(raw)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("%s holds no certificate: expected PEM (-----BEGIN CERTIFICATE-----) or DER, as the server publishes at management/other/ca.cert.pem and ca.cert.der", path)
	}
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out, nil
}

// CA returns the stored bundle, or nil if none.
func (st *State) CA() []byte {
	b, _ := os.ReadFile(filepath.Join(st.Dir, caFile))
	return b
}

// writeFile writes atomically (temp file plus rename) so a crash mid-write
// cannot leave a truncated key or certificate.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
