package enroll

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/FOGProject/fog-agent/internal/directory"
	"github.com/FOGProject/fog-agent/internal/identity"
	"github.com/FOGProject/fog-agent/internal/inventory"
	"github.com/FOGProject/fog-agent/internal/network"
	"github.com/FOGProject/fog-agent/internal/printers"
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
	"github.com/FOGProject/fog-agent/internal/secureboot"
	// The observed program list, aliased because `software` above is the
	// desired-state install capability: two different things (design 0006).
	softwarefacts "github.com/FOGProject/fog-agent/internal/software"
	"github.com/FOGProject/fog-agent/internal/usersession"
)

// Protocol is the agent protocol version this build speaks.
const Protocol = 1

// Request is the enroll body (protocol-v1.md).
type Request struct {
	Features     []string      `json:"features,omitempty"`
	Protocol     int           `json:"protocol"`
	AgentVersion string        `json:"agent_version"`
	OS           string        `json:"os"`
	Arch         string        `json:"arch"`
	Hostname     string        `json:"hostname"`
	Identity     identity.Host `json:"identity"`
	CSRPEM       string        `json:"csr_pem"`
	Token        string        `json:"token,omitempty"`
}

// Response is the enroll reply. Which fields are set depends on Status.
type Response struct {
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
	HostID     int    `json:"host_id,omitempty"`
	// CertificatePEM is the issued leaf followed by its issuing chain, which
	// is what the agent presents on every later connection.
	CertificatePEM string `json:"certificate_pem,omitempty"`
	NotAfter       string `json:"not_after,omitempty"`
}

// Terminal statuses.
const (
	StatusIssued      = "issued"
	StatusPending     = "pending"
	StatusDenied      = "denied"
	StatusUnsupported = "unsupported"
)

// Client talks to the agent API. It trusts only the CA bundle it was
// given, never the OS store, and after enrollment it presents the issued
// certificate on every connection (design doc 5.2).
type Client struct {
	ServerURL string
	HTTP      *http.Client
	tlsConfig *tls.Config
}

// ErrUnauthorized is returned by Poll when the server answers 401 for a
// reason that is not about this agent's binding: no certificate reached the
// application, the database was unreachable, a proxy answered, or the
// webroot does not serve the agent routes at all. The certificate may well
// still be good, so the caller must NOT throw it away on this.
var ErrUnauthorized = errors.New("server refused this agent's request")

// ErrCertificateUnknown is the one 401 that means what it says: the server
// has this request's certificate and it binds to no live host. Only this
// justifies discarding the identity and enrolling again.
//
// The split exists because the single sentinel cost a lab fleet its
// identities on 2026-09-04. The webroot was rolled back to a build with no
// agent routes, every poll answered 401 with an EMPTY body, and the agent
// discarded a working certificate four minutes later -- having logged
// "body is not JSON" first, so it had the evidence that this was not a
// considered answer and dropped the certificate regardless. Re-enrolling
// needs an admin to approve each host, so one rollback becomes fleet-wide
// manual work.
var ErrCertificateUnknown = errors.New("server does not recognize this agent's certificate")

// unauthorizedReason is the 401 body the server sends (Route::$agentAuthReason).
type unauthorizedReason struct {
	Reason string `json:"reason"`
}

// classifyUnauthorized decides whether a 401 is about this agent's binding.
// Anything the server does not explicitly call `unknown_certificate` --
// including an unparseable or empty body, which is what a rolled-back or
// proxied server sends -- is the safe answer: refuse, but keep the key.
func classifyUnauthorized(raw []byte) error {
	var r unauthorizedReason
	if err := json.Unmarshal(raw, &r); err != nil {
		return ErrUnauthorized
	}
	if r.Reason == "unknown_certificate" {
		return ErrCertificateUnknown
	}
	return ErrUnauthorized
}

// PollRequest is the poll body (protocol-v1.md).
type DirectoryAttempt struct {
	Phase       string `json:"phase"`
	AttemptID   string `json:"attempt_id,omitempty"`
	HostID      int    `json:"host_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type PollRequest struct {
	DirectoryObservation *DirectoryObservation `json:"directory_observation,omitempty"`
	DirectoryAttempt     *DirectoryAttempt     `json:"directory_attempt,omitempty"`
	Features             []string              `json:"features,omitempty"`
	Identity             *identity.Host        `json:"identity,omitempty"`
	AgentVersion         string                `json:"agent_version"`
	// AppliedRevision is the revision this agent last applied, compared
	// by the server for equality only: the desired state rides the answer
	// when it differs. Empty means "send it".
	AppliedRevision string `json:"applied_revision"`
	// WantState asks for the desired state even at the same revision (a
	// software drift check needs the set without the revision moving).
	WantState bool `json:"want_state,omitempty"`
	// Inventory and Software are facts about the host, carried up the same
	// route as the desired state comes down (design 0006). They are the
	// desired-state mechanism in reverse: present only when the agent's own
	// content hash moved, or when the server asked with want_*. Absent is
	// "nothing new", never "nothing installed".
	Inventory *inventory.Inventory    `json:"inventory,omitempty"`
	Software  []softwarefacts.Program `json:"software,omitempty"`
	// Directory is what directory the machine is actually a member of and
	// where its computer object actually sits (design 0009). Same hash gate
	// as the two above, and the same rule about absence: absent is "nothing
	// new", never "this machine left its domain".
	Directory *directory.Directory `json:"directory,omitempty"`
	// Printers is what is actually installed on the machine (design 0010
	// §3). Same hash gate, and the same rule about absence: absent is
	// "nothing new", never "this machine has no printers" -- the server
	// treats a reported list as complete, so a false empty would mark
	// every assigned printer as missing.
	Printers *printers.Printers `json:"printers,omitempty"`
	// Network is which links the machine is on (design 0011 §3). Same
	// hash gate, and the same rule about absence. This is the fact that
	// lets the server answer "which awake machine shares a link with the
	// sleeping one", which is the whole basis of the wake relay.
	Network *network.Network `json:"network,omitempty"`
	// SecureBoot is what the firmware says about Secure Boot (design
	// 0012): the platform and the two raw variable bytes, never a state
	// name. The server maps them with the same call it uses on the ones
	// iPXE sends, so the six-way vocabulary stays in one place. Same hash
	// gate and the same rule about absence as the blocks above.
	SecureBoot *secureboot.State `json:"secureboot,omitempty"`
	// Sessions is the user-session report (design 0008): who is logged on
	// now, and which sessions the agent watched end. Absent when the host's
	// usertracker module is off, or when this platform has no collector --
	// and absent is not the same as an empty open set, which would tell the
	// server to close every session it holds for this host.
	Sessions *usersession.Report `json:"sessions,omitempty"`
}

// PollResponse is what the server can do for this host right now.
type PollResponse struct {
	DirectoryCheck  *DirectoryCheck           `json:"directory_check,omitempty"`
	DirectoryRejoin *directoryjoin.RejoinPlan `json:"directory_rejoin,omitempty"`
	DirectoryHold   bool                      `json:"directory_hold"`
	Status          string                    `json:"status"`
	Protocol        int                       `json:"protocol"`
	Host            struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"host"`
	// Revision is opaque: the agent compares it with the one it applied
	// and never reads anything into it (protocol-v1.md).
	Revision     string `json:"revision"`
	PollInterval int    `json:"poll_interval"`
	ServerTime   string `json:"server_time"`
	// State is the desired state, present when Revision differs from the
	// applied revision the agent sent, or when it asked for it.
	State *DesiredState `json:"state,omitempty"`
	// WantInventory and WantSoftware ask for a fact block the server has
	// no current hash for -- a fresh enrollment, a restored database, a
	// cleared row -- so the agent sends it even though nothing changed
	// locally (design 0006 §2).
	WantInventory  bool `json:"want_inventory,omitempty"`
	WantSoftware   bool `json:"want_software,omitempty"`
	WantDirectory  bool `json:"want_directory,omitempty"`
	WantPrinters   bool `json:"want_printers,omitempty"`
	WantNetwork    bool `json:"want_network,omitempty"`
	WantSecureBoot bool `json:"want_secureboot,omitempty"`
	// Error is the server's human sentence when Status is not "ok". FOG
	// already sends one (Route's agent error path, and the schema-update
	// answer), and without this field the agent read the status word and
	// dropped the explanation -- so a log line said `status "error"` and
	// nothing about what the error was.
	Error string `json:"error,omitempty"`
	// CollectFacts is the server's gate (FOG_AGENT_INVENTORY_ENABLED). A
	// pointer because absent and false mean different things here: absent
	// is a server too old to have the setting, and the agent keeps
	// collecting; false is an admin who turned it off, and the agent
	// stops. Collapsing them would make every pre-facts server silently
	// switch inventory off.
	CollectFacts *bool `json:"collect_facts,omitempty"`
	// CollectSessions carries FOG's usertracker module resolved for this
	// host. A pointer for the same reason as CollectFacts: absent means an
	// older server that has never heard of it, which must not read as an
	// admin having switched it off.
	CollectSessions *bool `json:"collect_sessions,omitempty"`
}

// DesiredState is what the server wants this host to look like
// (protocol-v1.md). Blocks are present only for the capabilities listed.
type DesiredState struct {
	Revision     string            `json:"revision"`
	Capabilities []string          `json:"capabilities"`
	Hostname     *hostname.Desired `json:"hostname,omitempty"`
	// Task is the FOG task waiting to boot this machine into imaging,
	// present only while one is queued (capability taskreboot).
	Task *reboot.Task `json:"task,omitempty"`
	// Reboot is the policy every reboot obeys; sent with any state.
	Reboot *reboot.Policy `json:"reboot,omitempty"`
	// Snapins is the host's snapin queue in run order (capability snapin).
	Snapins []snapin.Task `json:"snapins,omitempty"`
	// Software is the desired package set and its drift interval
	// (capability software).
	Software *software.Policy `json:"software,omitempty"`
	// Power is the host's shutdown and reboot schedules plus any
	// on-demand action waiting (capability power).
	Power *power.Policy `json:"power,omitempty"`
	// Printers is the host's assigned print queues and how far FOG is to
	// go in enforcing them (capability printers).
	Printers *printerset.Policy `json:"printers,omitempty"`
	// Update is the version this host should be running, and optionally
	// where its signed manifest lives (capability update, design 0015).
	// Naming a version is all the server gets to do: what that version
	// IS comes from a manifest signed under a root compiled into this
	// binary, so a compromised server can pick which published version a
	// fleet runs and cannot publish one.
	Update *update.Desired `json:"update,omitempty"`
	// Directory is the domain the host should be joined to, with the
	// credential to do it (capability directory). Present ONLY for a host
	// the server believes is not joined and has a domain configured, so a
	// joined estate carries no join credential at all (design 0009 §6).
	// The credential inside redacts itself under every printer and
	// marshaler in this process, which is what keeps it out of `--once`
	// output and out of the state directory.
	Directory *directoryjoin.Policy `json:"directory,omitempty"`
	// Wake is the FOG hosts on this machine's own links that the server
	// wants woken (capability wake, design 0011). Present only when there
	// is a wake pending for a neighbor, which is almost never. There is
	// deliberately no destination in it: the agent broadcasts on its own
	// interfaces, so an agent cannot be aimed.
	Wake *wake.Policy `json:"wake,omitempty"`

	// AutoLogout is the idle-logoff policy (design 0014). Absent means the
	// capability is off for this host, which is different from a policy of
	// zero minutes only in that it also clears whatever was stored.
	AutoLogout *autologout.Policy `json:"autologout,omitempty"`
	// Activation is the host's Windows product key (design 0016). Present
	// only when the host has a valid key and enrolled as Windows; absent
	// means do nothing, never uninstall. The key redacts itself the way
	// the directory credential does.
	Activation *activation.Desired `json:"activation,omitempty"`
}

// ResultRequest is what the agent reports for one capability.
type ResultRequest struct {
	Revision   string `json:"revision"`
	Capability string `json:"capability"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	// Item is a report about one server-owned thing under the capability
	// (a snapin task, a software entry): the server keeps the row, reads
	// the exit code against its return-code table and answers an outcome
	// the agent acts on. Without an item the report is one audit line.
	Item *ResultItem `json:"item,omitempty"`
}

// ResultItem identifies the thing reported on and carries what the
// server's report class for the capability reads: the item's own status
// vocabulary, the raw exit code, the output tail, and for software the
// version the host has now.
type ResultItem struct {
	AttemptID        string  `json:"attempt_id,omitempty"`
	ConfigRevision   string  `json:"config_revision,omitempty"`
	TaskID           int     `json:"task_id"`
	NativeStatus     *uint32 `json:"native_status,omitempty"`
	SecureChannel    string  `json:"secure_channel,omitempty"`
	BootChanged      bool    `json:"boot_changed,omitempty"`
	CurrentName      string  `json:"current_name,omitempty"`
	Netbios          string  `json:"netbios"`
	Domain           string  `json:"domain,omitempty"`
	ID               int     `json:"id"`
	Status           string  `json:"status"`
	ExitCode         int     `json:"exit_code"`
	InstalledVersion string  `json:"installed_version,omitempty"`
	// Packets is how many datagrams a wake relay actually put on the wire
	// (capability wake). Carried as its own field and not left to the
	// detail sentence because the server stores it as a number an admin
	// sorts a report by -- and because "sent" with a count of zero is a
	// lie the existing wake path has no way to catch.
	Packets int    `json:"packets,omitempty"`
	Details string `json:"details,omitempty"`
}

// refuseRedirect stops the HTTP client following a 3xx and reports where it
// was being sent, because a redirect is never a valid answer to an API call
// and following one destroys the evidence.
//
// Observed in the lab on 2026-09-04. While the server's schema was mid-
// upgrade, FOG answered every poll with a redirect to its schema updater --
// and a RELATIVE one, `../management/index.php?node=schema`. Go resolved
// that against /fog/agent/v1/ into /fog/agent/management/index.php, PHP-FPM
// said "Primary script unknown", and the agent logged
//
//	poll: HTTP 404, body is not JSON: File not found.
//
// every five minutes across the fleet. Nothing in that line points at a
// schema upgrade, which is the actual and entirely ordinary cause.
//
// Now the agent reports the 3xx and its Location, so the next person reads
// "server redirected to ...?node=schema" and knows to finish the upgrade.
func refuseRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf(
		"server redirected the request to %s; the API never redirects, so "+
			"this is a server that is not serving the agent routes right "+
			"now (a pending schema update answers exactly like this)",
		req.URL,
	)
}

// NewClient builds a client that verifies the server against caPEM. An
// empty bundle is refused: enrolling against an unverified server would let
// anyone on the path hand the agent a certificate for a server they control.
func NewClient(serverURL string, caPEM []byte) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("enroll: CA bundle contains no certificates")
	}
	return newClient(serverURL, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}), nil
}

// NewSystemTrustClient builds a client that verifies the server against this
// machine's trust store and the server's name, the way a browser does. It is
// for a server whose web UI runs on a public or corporate certificate that
// the probe found this machine already trusts (design 0002). It is never a
// fallback for a pinned CA that stopped verifying.
func NewSystemTrustClient(serverURL string) *Client {
	return newClient(serverURL, systemTrustConfig(""))
}

// systemRoots is the pool a system-trust connection verifies against. nil
// is the operating system's own store, and on Windows and macOS the
// platform verifier a browser on that machine uses. A variable only so a
// test can stand a throwaway CA in for the machine's store.
var systemRoots = func() *x509.CertPool { return nil }

// systemTrustConfig verifies against systemRoots. An empty serverName is
// filled in per connection from the address, which is what http.Transport
// does; a raw dial has to name it.
func systemTrustConfig(serverName string) *tls.Config {
	return &tls.Config{RootCAs: systemRoots(), ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func newClient(serverURL string, cfg *tls.Config) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		HTTP: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: cfg},
			CheckRedirect: refuseRedirect,
		},
		tlsConfig: cfg,
	}
}

// UseCertificate presents the issued certificate (the leaf and its chain,
// as SaveIssued stored them) with the agent's key on every connection from
// now on. The chain rides along so the server can verify with only the
// root on file; nginx and Apache both accept depth 2.
func (c *Client) UseCertificate(certPEM []byte, key *ecdsa.PrivateKey) error {
	var chain [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return errors.New("certificate PEM contains no certificates")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	c.tlsConfig.Certificates = []tls.Certificate{{Certificate: chain, PrivateKey: key, Leaf: leaf}}
	// A connection opened before this call carries no certificate and
	// would be reused for the next request; the server would then see an
	// anonymous caller and answer 401. New connections pick up the config.
	if t, ok := c.HTTP.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// Poll asks the server what it can do for this host and records the
// check-in. 401 is ErrUnauthorized; anything else unexpected is an error
// with the status in it.
func (c *Client) Poll(ctx context.Context, req PollRequest) (*PollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	body, encoding := maybeGzip(body)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/agent/v1/poll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	if encoding != "" {
		hr.Header.Set("Content-Encoding", encoding)
	}
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, explainUnreachable(err, c.ServerURL)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, classifyUnauthorized(raw)
	}
	var out PollResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("poll: HTTP %d, body is not JSON: %.200s", resp.StatusCode, raw)
	}
	if resp.StatusCode != http.StatusOK || out.Status != "ok" {
		if out.Error != "" {
			return nil, fmt.Errorf("poll: HTTP %d, %s (status %q)",
				resp.StatusCode, out.Error, out.Status)
		}
		return nil, fmt.Errorf("poll: HTTP %d with status %q", resp.StatusCode, out.Status)
	}
	return &out, nil
}

// pollGzipThreshold is the body size above which the poll is compressed.
// A poll carrying no facts is a few hundred bytes and gains nothing from
// compression; one carrying a package-managed host's software list measured
// 388 KB, and 37 KB gzipped (2833 packages, 2026-09-04). Above the
// threshold the saving is an order of magnitude, and it keeps the body
// under the 1 MB nginx and Apache accept by default.
const pollGzipThreshold = 16 << 10

// maybeGzip compresses a request body once it is worth it, returning the
// bytes to send and the Content-Encoding to declare (empty for none). Any
// compression failure returns the original body: a larger request is
// always better than a failed poll.
func maybeGzip(body []byte) ([]byte, string) {
	if len(body) <= pollGzipThreshold {
		return body, ""
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return body, ""
	}
	if _, err := zw.Write(body); err != nil {
		return body, ""
	}
	if err := zw.Close(); err != nil {
		return body, ""
	}
	return buf.Bytes(), "gzip"
}

// RenewLead is how long before expiry the agent renews. A third of the
// one-year life the server issues, so a machine that is off for a term
// still comes back inside its certificate; an agent that misses the window
// falls through to the 401 path and an admin, which is the right outcome
// for a certificate that actually lapsed.
const RenewLead = 120 * 24 * time.Hour

// RenewDue reports whether the leaf in certPEM expires within RenewLead of
// now. An unparseable certificate is due: renewing it is the only move
// that can improve things.
func RenewDue(certPEM []byte, now time.Time) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return now.Add(RenewLead).After(leaf.NotAfter)
}

// Renew asks for a new certificate for the same key, over the connection
// the current certificate authenticates. The reply is the enroll "issued"
// shape and is stored the same way. 401 is ErrUnauthorized, as for Poll.
func (c *Client) Renew(ctx context.Context, csrPEM []byte) (*Response, error) {
	body, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/agent/v1/renew", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, explainUnreachable(err, c.ServerURL)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, classifyUnauthorized(raw)
	}
	var out struct {
		Response
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("renew: HTTP %d, body is not JSON: %.200s", resp.StatusCode, raw)
	}
	if resp.StatusCode != http.StatusOK || out.Status != StatusIssued {
		return nil, fmt.Errorf("renew: HTTP %d with status %q: %s", resp.StatusCode, out.Status, out.Error)
	}
	return &out.Response, nil
}

// authed does one JSON exchange over the certificate: 401 is
// ErrUnauthorized, a non-JSON body is an error with the status in it, and
// anything else is decoded into out for the caller to judge.
func (c *Client) authed(ctx context.Context, method, path string, in any, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	hr, err := http.NewRequestWithContext(ctx, method, c.ServerURL+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	hr.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return 0, explainUnreachable(err, c.ServerURL)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return resp.StatusCode, ErrUnauthorized
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d, body is not JSON: %.200s", path, resp.StatusCode, raw)
	}
	return resp.StatusCode, nil
}

// Result reports what one capability did at one revision, or with an
// item what happened to one thing under it. The outcome is the server's
// reading of an item's exit code; empty for a report without an item.
func (c *Client) Result(ctx context.Context, r ResultRequest) (string, error) {
	var out struct {
		Status  string `json:"status"`
		Outcome string `json:"outcome"`
		Error   string `json:"error"`
	}
	code, err := c.authed(ctx, http.MethodPost, "/agent/v1/result", r, &out)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK || out.Status != "ok" {
		return "", fmt.Errorf("result: HTTP %d with status %q: %s", code, out.Status, out.Error)
	}
	return out.Outcome, nil
}

// Payload streams the bytes behind one thing under a capability into w:
// for "snapin", the file of one task, and fetching it is what marks the
// task in progress on the server. One route for every kind of payload.
func (c *Client) Payload(ctx context.Context, capability string, id int, w io.Writer) error {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/agent/v1/payload/%s/%d", c.ServerURL, capability, id), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return explainUnreachable(err, c.ServerURL)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s payload: HTTP %d: %s", capability, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// Outcomes the server hands back for a reported snapin task, from the
// snapin's return-code table applied to the raw exit code.
const (
	OutcomeSuccess = "success"
	OutcomeReboot  = "reboot"
	OutcomeRetry   = "retry"
	OutcomeFailed  = "failed"
)

// Enroll sends one request and decodes the reply. Non-JSON or unexpected
// HTTP statuses are errors; the four protocol statuses are returned as data
// so the caller decides what to do with each.
func (c *Client) Enroll(ctx context.Context, req Request) (*Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ServerURL+"/agent/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(hr)
	if err != nil {
		return nil, explainUnreachable(err, c.ServerURL)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("enroll: HTTP %d, body is not JSON: %.200s", resp.StatusCode, raw)
	}
	switch {
	case resp.StatusCode == 200 && out.Status == StatusIssued,
		resp.StatusCode == 202 && out.Status == StatusPending,
		resp.StatusCode == 403 && out.Status == StatusDenied,
		resp.StatusCode == 426 && out.Status == StatusUnsupported:
		return &out, nil
	}
	return nil, fmt.Errorf("enroll: HTTP %d with status %q", resp.StatusCode, out.Status)
}
