# Agent protocol v1: enrollment

Status: DRAFT 2026-09-03. The agent owns this contract (design doc 5.1); the
server implements it under `/agent/v1`. JSON both ways, UTF-8, `Content-Type:
application/json`.

## POST /agent/v1/enroll

Server-authenticated TLS only (the agent has no certificate yet). The agent
trusts the CA bundle written at bootstrap, never the OS store. Idempotent: the
agent repeats the identical request until it gets a terminal answer.

Request:

```json
{
  "protocol": 1,
  "agent_version": "0.1.0",
  "os": "windows", "arch": "amd64",
  "hostname": "LAB-PC-07",
  "identity": {
    "system_uuid": "…", "system_serial": "…", "board_serial": "…",
    "chassis_asset": "…", "smbios_version": "3.2",
    "macs": ["cc:48:3a:5e:11:aa"]
  },
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…",
  "token": "optional enrollment token"
}
```

The CSR's subject is ignored; the server sets the issued subject
(`CN=fog-agent host <id>`) so an agent cannot choose its own identity. Only
the public key and the proof of possession matter.

Responses:

| HTTP | `status` | Meaning | Agent behavior |
|---|---|---|---|
| 200 | `issued` | Approved. Body carries `host_id`, `certificate_pem` (leaf followed by its issuing chain), `not_after` | Store cert, switch to mTLS, done |
| 202 | `pending` | Waiting for an admin, a token, or a deploy. Body carries `reason` (`unknown-host`, `known-host-no-agent`, `rebind`) and `retry_after` seconds | Log once per reason change, sleep, repeat |
| 403 | `denied` | An admin denied this key. Body carries `reason` | Log, back off to hourly, repeat (a later approval must still be reachable) |
| 400 | `error` | The request is malformed (`reason`: `csr`) | Log, back off, repeat |
| 503 | `error` | The server accepted the request but could not sign (`reason`: `signing`); the row is kept | Log, retry after `retry_after` |
| 426 | `unsupported` | Server does not speak protocol 1 | Log, back off, repeat |

Approval paths on the server, in order of evaluation:

| Path | Condition | Outcome |
|---|---|---|
| Token | `token` present, valid, unspent (or multi-use and unexpired) | Issue; an unknown machine was already created as a pending host and is un-pended by the issue; audit `agent.enroll` via `token` |
| Post-image | identity resolves to a host with no conflict, and the host's last deploy completed within `FOG_AGENT_ENROLL_DEPLOY_WINDOW` hours (default 24, 0 disables) | Issue and (re)bind; audit via `deploy` |
| Admin | everything else | Pending row; on approve issue and audit via `admin` with the user; on deny record the key fingerprint so the same key returns `denied` |

An unknown machine becomes a **pending host** immediately (description
"Pending Registration created by FOG_AGENT"), with an inventory row carrying
its firmware identity, so it appears where admins already look for pending
registrations. Approving the enrollment un-pends the host. The agent never
learns a host id until issue, so nothing about the pending host reaches it.

Reasons a request waits: `unknown-host`, `known-host-no-agent`, `rebind`
(the host already has an agent key), `identity-conflict` (firmware and MACs
name different hosts; the firmware's host is kept and the admin sees the
conflict), `reissue` (same key, certificate already collected), `no-mac`.

A pending row holds the request verbatim (identity, hostname, key
fingerprint, CSR) so approval signs exactly what was presented. A host with a
live certificate that receives a new enrollment from the same identity pends
with reason `rebind`; approving it revokes the old fingerprint.

## What a pending agent may do

Nothing. No other route accepts a request without a client certificate the
server issued, so "pending" is enforced by TLS, not by application checks.

## POST /agent/v1/poll

The first authenticated call, the hard floor's heartbeat, and the one
place the agent learns what it should look like. Every route under
`/agent/v1/` other than enroll is reachable only with the client
certificate enrollment issued: the web server verifies it against the agent
CA bundle on the TLS handshake (`ssl_verify_client optional` /
`SSLVerifyClient optional`, so a browser is never asked for one), and the
router re-verifies the chain against the same bundle and binds the key
fingerprint to exactly one live, non-pending host before any route matches.
No token, no session, no `mac=`.

Request:

```json
{"agent_version": "1.2.3", "applied_revision": "3f1c9a0b2d4e5f60", "want_state": false}
```

`applied_revision` is the revision this agent last converged, empty on a
fresh agent and on a build that has just learned a capability. `want_state`
asks for the state even when that revision is current: the software drift
check needs the set without anything having moved.

The request also carries **facts** -- what the agent has observed about its
own host, as opposed to what it has applied:

```json
{"agent_version": "1.2.3", "applied_revision": "3f1c9a0b…", "want_state": false,
 "inventory": {"sysman": "Dell Inc.", "…": "…"},
 "software": [{"name": "openssh-server", "version": "9.6p1", "source": "rpm", "…": "…"}],
 "directory": {"joined": true, "kind": "ad", "domain": "corp.example.com", "netbios": "CORP",
               "computer_dn": "CN=WS-014,OU=Sales,DC=corp,DC=example,DC=com",
               "machine_account": "WS-014$", "site": "HQ"},
 "network": {"interfaces": [{"name": "eno1", "mac": "cc:48:3a:5e:11:aa",
                            "ipv4": "10.20.30.14", "prefix": 24,
                            "network": "10.20.30.0", "broadcast": "10.20.30.255",
                            "up": true, "wireless": false}]},
 "secureboot": {"platform": "efi", "secure_boot": "01", "setup_mode": "00"},
 "sessions": {"open": [{"key": "2", "user": "telliott", "domain": "LAB", "type": "console",
                        "state": "active", "started_at": "2026-09-04T09:12:03Z"}],
              "closed": [{"key": "3", "user": "tom", "type": "remote", "state": "active",
                          "started_at": "2026-09-04T07:01:44Z", "ended_at": "2026-09-04T08:55:10Z",
                          "end_reason": "logout"}]}}
```

A fact block is present only when the agent's own content hash for it moved,
or when the previous answer asked with `want_inventory` / `want_software` /
`want_directory` / `want_printers` / `want_network` / `want_secureboot`.

`secureboot` carries raw observations rather than a state name (design
0012): the platform and the two firmware bytes, which the server maps with
`SecureBootState::fromBootRequest()` -- the same call it applies to what
iPXE sends on a netboot. Naming the state here would put that six-way
mapping in two languages, and the vocabulary was copied verbatim from FOS
precisely so there would only ever be one of it. A machine with no honest
mapping onto the six names (macOS) sends no block at all.

`network` is the one collected on **every** poll rather than on the agent's
hourly fact interval: it is a single `net.Interfaces()` call, where
enumerating a package-managed host's packages is the most expensive thing
the agent does, and it is what the server picks wake relays from — so an
hour of staleness is an hour of asking a laptop that has gone home to
broadcast on a subnet it left. It still only goes on the wire when its hash
moves. The server recomputes `network` and `broadcast` from the address and
prefix and discards the reported values: a host that could claim a network
it is not on could join any link's relay group it liked.
This is the conditional fetch above run in reverse, and it has the same
consequence: **absent is "nothing new", never "nothing there"**. An agent
whose collector cannot run on this platform sends no block rather than an
empty one, because the server treats a reported list as complete.

**The poll request may be gzipped.** When the body exceeds 16 KB the agent
compresses it and sets `Content-Encoding: gzip`; the server decodes on that
header alone. A measured Linux host's software list is 388 KB of JSON and
37 KB gzipped, which is the difference between fitting the 1 MB body limit
nginx and Apache ship with and not. No other route compresses: nothing else
the agent sends is big enough to be worth a decode.

Response `200`:

```json
{
  "status": "ok",
  "protocol": 1,
  "host": {"id": 231, "name": "7550precision"},
  "revision": "3f1c9a0b2d4e5f60",
  "poll_interval": 300,
  "server_time": "2026-09-03T12:43:21-05:00",
  "state": {"revision": "3f1c9a0b2d4e5f60", "capabilities": ["hostname"], "hostname": {"name": "lab-01", "enforce": true}},
  "want_inventory": false,
  "want_software": false,
  "want_directory": false,
  "collect_facts": true,
  "collect_sessions": true
}
```

`state` is present when `revision` is not the `applied_revision` the agent
sent, or when it asked for it; otherwise the answer stops at `server_time`
and the agent has nothing to do but sleep `poll_interval`. This is a
conditional fetch on a POST, the way an ETag works on a GET, done as a POST
because the poll also writes: the server records `hostAgentCheckin` and
`hostAgentVersion` on every one.

`want_inventory`, `want_software` and `want_directory` ask for a fact block the server holds
no current hash for -- a fresh enrollment, a restored database, an admin who
cleared the row. They are the server's half of the same conditional: it can
always force a resend, and the agent honors the request on its next poll
whether or not anything changed locally.

`directory` is design 0009: what directory the machine is actually a member
of, and where its computer object actually sits. It follows the hash rule --
membership moves when someone joins a machine to a domain, so the block is
almost never sent. `joined: false` with `kind` of `workgroup` or `none` is a
real answer meaning "asked, and it is in none"; a machine whose platform has
no collector, or where the probe failed, sends **no block at all**, because a
zero block would tell the server every host had left its domain.

`computer_dn` is the field the server needs to move a computer object between
OUs without the machine's involvement (0009 §5). Empty is normal -- no Linux
join tool exposes it -- and the server falls back to searching for
`machine_account`.

`sessions` is design 0008 and does **not** follow the hash rule above. The
open set is the server's evidence a session is still alive, so it is sent
whenever it differs from the last one the server acknowledged, whenever a
closure is waiting, and at least hourly regardless. `closed` carries only
sessions the agent watched end; a session that vanished because the machine
lost power is closed by the server, at the host's last contact, marked
`inferred`. **An absent `sessions` block is "nothing new"; an `open: []` is
"nobody is logged on" and closes every session the server holds.**

`collect_sessions` is FOG's `usertracker` module resolved for the host, and
carries the same absent-is-not-false rule as `collect_facts` below. An agent
told `false` stops reading sessions at all rather than reading and
discarding: the privacy-relevant act is looking at who is logged on.

`collect_facts` is the install's gate (`FOG_AGENT_INVENTORY_ENABLED`) and is
always stated, never omitted. An agent stops running its collectors when it
is `false` -- the server would discard the block anyway, so gathering would
be pure cost on every host in the estate. **Absent is not `false`**: a server
too old to carry the field must not read as one that turned collection off,
so the agent leaves the setting alone when the key is missing and only
changes it when the server actually says something.

**The revision is opaque.** The agent compares it with the one it applied,
for equality, and does nothing else with it: never parses it, never orders
two of them, never treats it as a version number or a time. Today it is a
digest of the desired state; tomorrow it may be a cheaper thing the server
can compute without building the state. An agent that reads anything into
it closes that door for every server it will ever talk to.

| Status | Meaning | Agent does |
|---|---|---|
| 200 | Bound host, answered | Converge `state` if present, then sleep `poll_interval` and poll again |
| 401 | No verified certificate, or one bound to no live host (deleted, re-enrolled elsewhere, still pending) | Drop the certificate, keep the key, enroll again |

The 401 is the reimage/rebind path in practice: a host deleted from FOG and
its agent left running comes back as `unknown-host` pending, with the same
key, and waits for an admin like any new machine.

## The desired state

What the host should look like, carried in the poll answer as `state`.
`capabilities` is the list from design 0001 5.1; empty is a valid answer and
the agent idles on it. A capability is listed when its legacy module is on for
the host (the global `FOG_CLIENT_*_ENABLED` setting and the host's resolved
module set, the same two checks the old client's endpoints make), so existing
per-host and per-group module choices carry over. Blocks appear only for the
capabilities listed; a server that does not offer something never describes
it.

```json
{
  "revision": "3f1c9a0b2d4e5f60",
  "capabilities": ["hostname"],
  "hostname": {"name": "lab-01", "enforce": true}
}
```

| Block | Source | Provider |
|---|---|---|
| `hostname` | the host record's name; `enforce` is the host's "Enforce Hostname / AD Join Reboots" flag, the admin's permission to reboot to finish a rename | `ensure hostname`: compares case-insensitively, sets only on a difference. Linux `hostnamectl` (no reboot), Windows `SetComputerNameEx` (reboot pending), macOS `scutil`. A Windows domain member is never renamed alone: the `directory` block renames it in the domain (design 0017). While the server's join cooldown holds that rename, the block carries `wait_until` (UTC, RFC 3339) and the agent reports `pending` with the time. With no rename and no `wait_until`, it reports `failed` with the reason |

Two more blocks serve the reboot coordinator (design 0001 section 6):

```json
{
  "capabilities": ["hostname", "taskreboot"],
  "task": {"id": 41, "type": "Deploy", "force": false},
  "reboot": {"grace": 60}
}
```

| Block | Source | Consumer |
|---|---|---|
| `task` | capability `taskreboot` (module `taskreboot`): the task waiting for this host in a state that needs it to boot into FOS, exactly what `Client\Jobs` answers the old client. `null` while none waits, so queueing or canceling a task moves the revision. `force` is FOG_TASK_FORCE_REBOOT | the coordinator records a reboot reason for the task, or withdraws it |
| `reboot` | sent with any non-empty capability list. `grace` is FOG_GRACE_TIMEOUT, seconds | the countdown logged-in users get before a forced reboot |

### The reboot coordinator

The only thing in the agent that reboots. Providers never do; a provider
whose change needs one reports `pending_reboot` and the coordinator
records a reason for it, forced if the host's `enforce` flag is set. A
waiting task is a reason too, forced if FOG_TASK_FORCE_REBOOT is on.
Reasons persist in the state file across restarts.

Every poll, with reasons outstanding, the coordinator counts logged-in
users (logind or `who` on Linux, WTS sessions on Windows, `who` on macOS)
and decides:

| Users | Any reason forced | Decision |
|---|---|---|
| none | either | reboot now |
| some | no | wait; reported as `reboot pending_reboot` with the count |
| some | yes | reboot after `grace` seconds, message shown to users |

The decision is reported as a result with capability `reboot`
(`applied` when a reboot was requested, `pending_reboot` when it waited),
so the host's audit shows why the machine went down or why it did not.

**Where this diverges from the old client:** the agent reboots **once per
task id**. A machine that comes back with the same task still queued did
not boot into FOS (boot order, no PXE on that segment), and the old
client's answer, rebooting it again every check-in, takes the machine
away from its user without fixing that. Cancel and re-queue the task to
ask again; a new task is a new id.

Two server-side facts that decide whether a capability appears at all:

- The capability list is the host's *resolved* modules intersected with the
  global `FOG_CLIENT_*_ENABLED` switches. FOG has no default tier in module
  resolution, so a host with no module rows has no capabilities. Hosts the
  agent creates get the `isDefault` modules at creation, the same as boot
  registration and the Host Management form (fogproject PR #1707).
- A host record whose name fails FOG's own rule (1 to 15 characters of the
  allowed set) is invalid, and an invalid host does not authenticate: the
  agent gets 401 and re-enrolls as `rebind`. The API refuses such a name, so
  this only bites on a name written straight into the database.

Proven 2026-09-03 on a throwaway Debian VM: rename in FOG, next poll saw the
revision move, `hostname: applied (fogagent-test -> fog-renamed)`, the
following run reported `unchanged`, both audited as `agent.result` with
auth source `agent`.

### Snapins

Capability `snapin` (module `snapinclient`). The block is the host's
snapin queue exactly as the server tasked it: `snapinTasks` rows in
`sequence` order, which the server wrote from its resolver -- the host's
own associations first, then its groups' grants in group order,
deduplicated. The agent runs them in that order and never re-sorts.

```json
{
  "capabilities": ["snapin"],
  "snapins": [
    {"task": 41, "snapin": 7, "name": "Install 7-Zip", "file": "7z.msi",
     "size": 1834496, "sha512": "…", "args": "/qn", "run_with": "msiexec.exe",
     "run_with_args": "/i", "timeout": 600, "action": "", "abort_on_fail": false,
     "pack": false}
  ]
}
```

For each task, in order:

| Step | Route | Server side |
|---|---|---|
| fetch | `GET /agent/v1/payload/snapin/{task}` | the task must belong to this host's own job (404 otherwise, the same message as "no such task"); marks the task, the job and the host's task in progress; streams the bytes from the storage node over the web tier's own FTP session, so the agent trusts only the server's certificate |
| verify | | the agent hashes as it downloads and refuses a sha512 that is not the one declared. That refusal is reported as status `hash_mismatch`, not retried: the file the server has is not the file it described, and the admin needs to see it |
| run | | `run_with run_with_args file args`, or the file itself when `run_with` is empty (made executable on Unix). A `pack` is a zip: it is unzipped, `[FOG_SNAPIN_PATH]` in `run_with` and `run_with_args` becomes that folder, and `run_with run_with_args` runs inside it; `args` is not used, as in the legacy client. On Windows the arguments reach CreateProcess as typed, `%VAR%` expanded, never split and re-quoted. `timeout` seconds then the whole process group is killed, status `timeout`; a payload that could not start, or a pack that will not unzip, is `cannot_run` |
| report | `POST /agent/v1/result` with `item: {id: task, status, exit_code, details}` | `status` is `ran` or one of the three above; `exit_code` is the program's own, untouched, meaningful only for `ran`; `details` the last 4 KB of output. The server answers `{"status":"ok","outcome":…}` |

**Outcome, decided by the server.** A raw exit code says nothing by
itself: an MSI answers 3010 for "installed, reboot to finish" and 1618
for "another installer is running, try later", and treating either as a
failure aborts jobs that did not fail. Each snapin carries a return-code
table (lines of `code=class`, the Intune defaults when empty: 0 and 1707
success, 3010 and 1641 reboot, 1618 retry, anything else failed) and the
server reads the code against it, for this agent and for the legacy
client alike:

| Outcome | Server | Agent |
|---|---|---|
| `success` | task complete | next task |
| `reboot` | task complete | forced reason for the reboot coordinator, then next task |
| `retry` | task back to queued, details kept | stops the queue for this poll; the next poll starts again here |
| `failed` | task complete; cancels the rest of the job when it aborts on failure | stops when the job aborts on failure, else next task |

A status other than `ran` is always `failed`. The task row keeps the raw
code, the status and the output; the outcome is what the UI shows.

The defaults are Windows codes. Linux and macOS hand the parent only the
low 8 bits of an exit status, so a script there cannot answer 3010 or
1618 (they arrive as 194 and 82); a non-Windows snapin that needs the
reboot or retry outcome maps the code it can actually return.

A fetch that fails (network, 503 from a node that is down) leaves the task
open and the revision unapplied; the next poll runs the queue again from
the first open task.

`action` (`reboot` or `shutdown`, from the snapin's flags) is a forced
reason for the reboot coordinator, the way the legacy client's post-snapin
restart was forced; every shutdown reason together means a shutdown, one
reason that needs the machine back means a reboot.

Payloads land under the state directory in a root-only directory named
by task id and are deleted after the run, whatever happened.

### Power

Capability `power` (module short name `powermanagement`), design 0004. The
block is the host's resolved shutdown and reboot schedules (its own rows and
its groups' grants, `wol` left out because the server sends that packet
itself) plus any on-demand action an admin has clicked:

```json
"power": {
  "schedules": [{"cron": "30 22 * * 1-5", "action": "shutdown"}],
  "ondemand":  [{"id": 41, "action": "reboot"}]
}
```

`cron` is the five-field form FOG stores (`minute hour day-of-month month
day-of-week`; `*`, lists, ranges and `/step`; day-of-month and day-of-week
both restricted means either matches). The agent fires schedules itself,
sleeping until the earlier of its next poll and its next firing, and each
firing is a forced reason to the reboot coordinator in that action's mode.

Each on-demand entry is handed to the coordinator as a forced reason and
acknowledged at once with `POST /agent/v1/result` `{capability: "power",
status: "applied", detail: "on-demand reboot accepted (id 41)"}`; that
report is what deletes the host's on-demand rows on the server, so an admin's
request stands until an agent has actually taken it. The coordinator's own
decision follows as a `reboot` result like any other.

### Software

Capability `software` (module short name `software`), design 0003. The
block is the desired package set in run order, resolved the way the snapin
queue is (the host's direct assignments, then its groups' grants in group
order, deduplicated), plus the server's drift interval:

```json
"software": {
  "drift_interval": 21600,
  "bootstrap": {"url": "", "nupkg_url": ""},
  "entries": [
    {"id": 3, "backend": "choco", "package": "googlechrome", "version": "latest",
     "state": "present", "source": "", "args": "", "timeout": 900}
  ]
}
```

`version` is `""` (any), `latest` (upgrade at every check) or an exact
version (pinned; installed with `--force` when the host has another).
`state` is `present` or `absent`. A disabled entry is left out, not sent as
absent: turning an entry off stops managing the package, it does not
remove it.

`bootstrap` is what the agent does when Chocolatey is missing. An empty
`url` (the default, `FOG_SOFTWARE_CHOCO_BOOTSTRAP_URL`) means nothing: every
entry reports `cannot_run` and the agent looks for the binary at each poll.
With a `url` the agent fetches that install script (trusting the system
roots plus the FOG CA, so the FOG server can host it) into its state
directory and runs it with PowerShell as SYSTEM, `nupkg_url`
(`FOG_SOFTWARE_CHOCO_NUPKG_URL`) becoming the script's
`chocolateyDownloadUrl` when set. The attempt is reported as a result on
the `software` capability, `applied` or `failed`, and the entries run right
after. A failed bootstrap is tried again at the next drift check, not every
poll. Windows only: elsewhere the bootstrap reports `failed` and says so.

The agent converges the set when the revision changes and again whenever
`drift_interval` seconds have passed since its last check, fetching the
state for that. One installed-list call from the backend, then each entry
in order, then a second list when anything ran so every report carries the
version the host ended with. Outcomes never hold the revision: a failed
install is reported and tried again at the next drift check, not every
poll. Only a report that did not reach the server keeps the revision
unapplied.

| Step | Route | Notes |
|---|---|---|
| report | `POST /agent/v1/result` with `item: {id, status, installed_version, exit_code, details}` | `status` is `converged`, `installed`, `upgraded`, `removed`, `timeout` or `cannot_run`; `exit_code` is the package manager's own, meaningful for the three action statuses; `details` the last 4 KB of output. The server answers `{"status":"ok","outcome":…}` |

The outcome is read the way a snapin's is, against the entry's return-code
table, with the snapin defaults plus Chocolatey's `350` (pending reboot
detected) as `reboot`. `converged` is always `success`; `timeout` and
`cannot_run` always `failed`. `reboot` becomes a non-forced reason for the
coordinator, so an installer that wants a reboot to finish waits for the
logged-in user, unlike a task or a snapin. The status row on the server
keeps the action word when it succeeded, else the outcome, else the
never-ran status verbatim, so the host's Software tab and the snapin
history read alike.

The Chocolatey backend is the `choco` executable at a path
(`%ProgramData%\chocolatey\bin\choco.exe` on Windows, `choco` on PATH
elsewhere), which is how FOG's own snapin templates call it and why the
pipeline can be proven with a shim on Linux. Detection is `choco list -r`
(`--local-only` added on 1.x, which 2.x rejects). A host without the
binary reports `cannot_run` for every entry.

### Printers

Capability `printers` (module short name `printermanager`), design 0010.
The block is the host's resolved printer assignments plus how far FOG is to
go in enforcing them:

```json
"printers": {
  "manage": "assigned",
  "default": "Accounts-HP4550",
  "printers": [
    {"id": 12, "name": "Accounts-HP4550",
     "uri": "socket://10.0.4.20:9100",
     "driver": "HP Universal Printing PCL 6"}
  ]
}
```

`manage` is `off`, `assigned` or `exclusive` — words rather than the
`0`/`a`/`ar` the legacy client is sent, which are not written down anywhere
an admin can see. `off` touches nothing; `assigned` installs and maintains
what FOG assigned and leaves everything else alone; `exclusive` also removes
what FOG did not assign.

`uri` is the device URI, derived on the server from the printer's type and
address when nothing was set explicitly, so a printer created years ago
still works. An empty `uri` is a configuration gap, not an instruction: the
agent attempts nothing and reports it against that printer, which is the
only way it becomes visible. An empty `driver` is a value — driverless, IPP
Everywhere — and not a missing field.

| Step | Route | Notes |
|---|---|---|
| report | `POST /agent/v1/result` with `item: {id, status, details}` | `status` is `converged`, `installed`, `updated`, `removed`, `failed` or `unsupported`; `details` is the provider's message, kept only for the two that did not settle. The server answers `{"status":"ok","outcome":…}` |

Every assigned printer is reported on every run, including the ones that
needed nothing: the server reads `converged` as "still true" and silence as
unknown. The four settled statuses clear any error recorded against the
printer, so a report never shows a stale message against a queue that is
now installed.

The **driver is never compared**. What the collector observes is the
spooler's own vocabulary (`printer-make-and-model` reads
`Canon MF650C Series UFR II`) and not the string that was passed to
`lpadmin -m`; comparing them would order an update on every poll that
changed nothing and found the same difference again forever. The URI is the
identity — it is what the spooler reports back verbatim and what decides
where the job goes — and the driver is applied at creation and left alone.

Removals under `exclusive` are performed but not reported per printer:
they are queues FOG never assigned, so there is no row to hang a result on.
They reach the server as the next facts report, simply gone from the
installed list (design 0010 §3).

The set is re-converged when the revision moves, and otherwise once an hour
on the facts cadence, so a queue somebody deleted comes back without an
admin having to touch the assignment.

### Wake

Capability `wake` (module short name `powermanagement`), design 0011. FOG
hosts on this machine's own links that the server wants woken:

```json
"wake": {"targets": [{"id": 41, "macs": ["00:11:22:33:44:55"]}]}
```

**There is no destination in it, and there must never be one.** The agent
broadcasts on its own interfaces' broadcast addresses and on
`255.255.255.255`, exactly as a storage node's `WakeOnLan::send()` does,
and there is no field in which a caller could name anywhere else. An agent
that accepted a destination would be a UDP reflector for whoever could
feed it one, and "only the server can feed it one today" is not a property
worth relying on.

Everything the agent enforces itself rather than trusting the server to
have got right: the payload is always exactly the 102-byte magic packet;
the MACs are re-parsed and re-serialized here, so a malformed one becomes
a refusal rather than a datagram; and at most `MaxTargets` (32) are acted
on per poll — a constant in the agent, not a number the server supplies,
because an agent whose traffic ceiling is set by whatever answers its poll
has no ceiling.

| Step | Route | Notes |
|---|---|---|
| report | `POST /agent/v1/result` with `item: {id, status, packets, details}` | `id` is the host that was woken — the only item report whose id is not the reporting host's own; `status` is `sent` or `failed`; `packets` is how many datagrams actually went out |

The server refuses a result for which there is no pending request naming
this sender and that target (404). That pending row is the authorization:
without it any enrolled agent could write a result against any host.

The block is absent for essentially every host on essentially every poll,
and absent is not an empty instruction.

### Directory

Capability `directory` (module short name `hostnamechanger`), design 0009 §6.
The block is present **only** for a host the server believes is not joined
and has a domain configured, so a joined estate — most of an estate, most of
the time — carries no join credential at all:

```json
"directory": {
  "domain": "corp.example.com",
  "netbios": "CORP",
  "ou": "OU=Workstations,DC=corp,DC=example,DC=com",
  "username": "CORP\\fogjoin",
  "password": "…",
  "reboot": true
}
```

The contrast is with the legacy client, which is sent `ADUser` and `ADPass`
in the answer to **every** check-in of **every** host with `useAD` set,
joined or not, forever. The server here omits the block entirely when the
host has never reported its membership (it does not know), when the host is
already in the right domain, when it is joined to a different one (the agent
would refuse), and for an hour after any attempt. That last one is not
politeness: a join that fails on a bad password is a failed authentication
against a domain controller, and one per host per poll is how a service
account with a lockout policy gets locked out.

One case sends it to a **joined** host (design 0017): a Windows host in the
right domain whose reported machine account is not the host's name (its
first 15 characters, plus `$`). The block then carries
`"rename_to": "<name>"`, and the agent renames the machine and its computer
object together with `NetRenameMachineInDomain`. The machine cannot rename
its own object without the credential. Without `rename_to`, the block means
"join". Same cooldown.

The agent holds the credential in memory only. It is never written to the
state directory and never logged — it redacts itself under every printer and
marshaler in the process, so `run --once` output shows `[redacted]`, and it
is zeroed after the attempt.

`ou` is the container the computer object is **created** in, which saves a
move that would otherwise follow every first join. Moving an
*already-joined* machine between OUs is not on this side at all: that is a
property of an object in a directory, so the server does it with one LDAP
Modify DN and the machine is not involved (design 0009 §5).

| Step | Route | Notes |
|---|---|---|
| report | `POST /agent/v1/result` with `item: {id, status, details}` | `id` is the agent's own host id — the row is its own membership; `status` is `joined`, `already_joined`, `renamed`, `failed`, `unsupported` or `refused`; `details` is the tool's message, kept only for the three that did not settle |

An item report and not a plain one because the join has its own vocabulary
and the outer `status` already carries the capability's
`applied`/`failed` — and `failed` means two different things in the two
places.

**The agent only ever joins.** It never unjoins, and a machine already in a
*different* domain is `refused`, not moved: getting it to the right one
means leaving the wrong one, which resets the computer account's password
and, where the object is recreated, costs it its SID, its group
memberships, its escrowed BitLocker keys and any certificate issued to it.
None of that may be a side effect of an admin editing a field.

Windows joins through `netapi32!NetJoinDomain` rather than `Add-Computer` or
`netdom`, and the reason is the credential: a command line is visible to
every process on the machine through the process table, and a PowerShell
script is captured verbatim by script block logging. The direct call takes
the password as a pointer in this process's own memory. Linux uses `adcli`,
or `realm` where adcli is absent, both of which take the password on stdin —
which is what picks them.

### Auto log out

Capability `autologout` (module short name `autologout`), design 0014. How
long a session may sit idle before the agent ends it:

```json
"autologout": {"minutes": 15, "warn_seconds": 60}
```

`minutes` is `Host::getAlo()` unchanged — the host's own `hostAutoLogOut`
row falling back to `FOG_CLIENT_AUTOLOGOFF_MIN`, where 0 disables.

**The five-minute floor is enforced on both sides.** The server does not
send the block below it and the agent ignores one that arrives anyway. A
two-minute idle timer logs people off while they are reading the screen,
and the legacy client refused it for that reason; duplicating the check
costs one comparison and means a policy that arrived wrong cannot log a
fleet off.

An absent block turns the capability off and clears what the agent stored,
which is different from `"minutes": 0` only in that a stored policy can
never outlive its removal from the server.

There is no `message` field in practice. The agent carries its own default
text, because a string set on the server is one the server cannot translate
into the language of whoever is sitting at the machine. The field exists in
the wire format for a site that wants to override it anyway.

**Unlike every other capability, this one is evaluated between polls** — on
the 30-second session sample, not on the poll. The policy is in minutes and
the poll interval is an admin's choice, so a fifteen-minute policy on an
hourly poll would otherwise warn somebody a minute before an event that
already happened. It also produces no result on the poll that carries it:
an idle timeout has no outcome until it fires.

### Activation

Capability `activation` (module short name `hostnamechanger`, the module the
legacy client activated from), design 0016. The host's product key:

```json
"activation": {"key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}
```

`key` is the host's `hostProductKey`, decoded and sent in the hyphenated
29-character form. The block is present only when that key is valid and the
host enrolled as `windows`. An absent block means do nothing; the agent
never uninstalls a key.

The key is a secret on the agent, like the directory password: never logged,
never stored, never in a result. It reaches the Software Licensing classes on
stdin, not on a command line.

| Result | When |
|---|---|
| `unchanged` | The installed key ends with the same five characters and Windows is licensed |
| `applied` | The agent installed the key, activated, or both. An activation error after a good install is still `applied`, with the code in `detail`: Windows retries activation itself |
| `failed` | The install was refused (wrong edition, bad key), or the platform is not Windows |

### Update

Capability `update`, design 0015. No legacy module stands behind it. The
server lists it when it has resolved an exact version for the host.

```json
"update": {
  "desired": "0.1.8",
  "manifest_url": "https://mirror.example.org/agent-stable.json",
  "manifest": "eyJjaGFubmVsIjoic3RhYmxlIiwi...",
  "signature": "eyJjaGFpbiI6WyItLS0tLUJFR0lO...",
  "artifact": 12
}
```

| Field | Meaning |
|---|---|
| `desired` | An exact version. The agent refuses anything else, `latest` included, with `bad_desired_version`. The server turns its update mode and rings into a version before it answers (design 0015 §2.2) |
| `manifest_url` | Optional. Where the signed manifest and its `.sig` live. Absent means the URL compiled into the agent |
| `manifest`, `signature` | Optional, and a pair. Standard base64 of the exact bytes of the signed manifest and of its detached envelope, as the server downloaded them. With both present and both decodable, the agent verifies these bytes and does not fetch `manifest_url`. With either one missing or not decodable, the agent ignores both and fetches `manifest_url` |
| `artifact` | Optional. The payload id of the server's copy of the file for this host's OS and architecture. Absent or 0 means the server holds no copy |

The agent checks an inline pair exactly as it checks a downloaded one: the
signature and chain against the root compiled into it, at the manifest's
`signed` time; the sequence floor; the maximum signature age; `expires`; and
the entry for `desired`, OS and architecture. A refused pair falls back once
to `manifest_url`, or to the compiled URL when that is absent. The agent
checks that copy the same way. A server whose release sync stopped holds a
manifest that expires, and the origin still serves a current one. When the
URL copy verifies, the agent reports nothing about the pair. When it fails
too, the detail leads with the code of the URL attempt and names both:
`signature_invalid: server copy: stale_manifest: the manifest has expired;
origin: signature_invalid: …`. With no URL at all, the refusal of the pair
is reported as it is.

**The file.** With `artifact` set, the agent fetches
`GET /agent/v1/payload/update/{artifact}` over its client certificate. It
hashes the bytes as they stream, against the size and sha256 in the manifest
entry. Any failure of that copy (transport, status, size or hash) falls back
once to the `url` in the manifest entry. The agent reports a failure only
when the fallback fails too, and the detail names both attempts:

| Server copy and origin | Detail code |
|---|---|
| both served bytes the manifest does not describe | `hash_mismatch` |
| any other pair of failures | `fetch_failed` |

The server's copy is not secret. The same bytes are on the release page, and
the agent trusts them only once the hash matches.

A server that sends none of `manifest`, `signature` or `artifact` gets the
behavior agents had before these fields existed. An agent older than these
fields ignores them and downloads from the manifest URL. That is why the
origin URL stays inside the signed manifest.

## POST /agent/v1/result

What one provider did at one revision, or what happened to one thing
under it. Same gate as poll. One route for every kind of report.

```json
{"revision": "3f1c9a0b2d4e5f60", "capability": "hostname", "status": "applied", "detail": "old-name -> lab-01"}
```

`status` is one of `applied`, `unchanged`, `pending_reboot`, `failed`. The
agent records the revision as applied only when no provider failed, so a
failure is retried on the next poll rather than forgotten. A report without
an item is recorded on the host as an `agent.result` audit row, which is
where FOG already shows what happened to a host, and answered `{"status":
"ok"}`.

A report **with an item** is about one server-owned row under the
capability, and the server answers with an outcome the agent acts on:

```json
{"revision": "3f1c9a0b2d4e5f60", "capability": "snapin", "status": "applied",
 "item": {"id": 41, "status": "ran", "exit_code": 3010, "details": "…"}}
```

```json
{"status": "ok", "outcome": "reboot"}
```

`item.id` names the row (a snapin task, a software entry); the rest of
`item` is what that capability's report class reads, in its own status
vocabulary (Snapins, Software above). The server dispatches on
`capability` to the report class, which keeps the row, reads the exit code
against its return-code table and decides the outcome. The per-item
identity and the two-way answer are real; a route per artifact type is
not, so a capability that gains item reports gains an entry in the
server's dispatch map and nothing on the path. A capability with no item
reports answers 400 to an item; the report classes' own codes (404 for a
row that is not this host's, 409, 503) pass through.

## POST /agent/v1/renew

Same gate as poll: the caller is already bound to its host by the certificate
it presents, and the body carries a request for the **same key**. The answer
is the enroll `issued` shape and the agent stores it the same way. Renewal is
same-key only; a new key is a new claim on the machine and goes through
enroll, where it pends as `rebind` for an admin. The old certificate is not
revoked: it binds to the same key and lapses on its own.

Request:

```json
{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."}
```

Response `200`:

```json
{"status": "issued", "host_id": 231, "certificate_pem": "...", "not_after": "2027-09-03 14:44:06"}
```

| Status | Meaning | Agent does |
|---|---|---|
| 200 | Renewed; `hostAgentNotAfter` updated, audited | Store it, present it from the next connection |
| 400 | Not a CSR, or one for a different key | Report; keep the current certificate |
| 401 | As for poll | Drop the certificate, keep the key, enroll again |
| 503 | Signing helper unavailable on this server | Report; retry next poll |

The agent renews inside `RenewLead` (120 days) of expiry, checked after each
successful poll, and `fog-agent renew` forces one at any time. A machine that
misses the window entirely falls through to the 401 path and an admin.

Server files behind this: `Agent\Principal` (verification and fingerprint),
the gate in `Route` before dispatch, and the installer publishing
`management/other/agent-ca-bundle.pem` (agent CA + root) for both the vhost
and PHP to verify against.

## The route rule

The agent surface is five routes, and the number is meant to stay small:

| Route | Transport shape |
|---|---|
| `POST /agent/v1/enroll` | no certificate yet; the request is the claim |
| `POST /agent/v1/poll` | JSON in, JSON out, conditional on a revision |
| `POST /agent/v1/result` | JSON in, a one-word answer |
| `GET /agent/v1/payload/{capability}/{id}` | bytes out, streamed |
| `POST /agent/v1/renew` | a CSR in, a certificate out |

**A new agent route is justified only by a new transport shape, never by a
new subject**: a new verb, a binary payload, or a different trust boundary.
A new capability, artifact type or report kind is a new value of
`capability` in the existing routes and a new block in the desired state.
The tell: if the proposed path contains a noun from the data model, it
fails. `snapin/{id}/result` and `software/{id}/result` were that shape, and
they are now one `item` on `result`; `snapin/{id}/file` is now
`payload/{capability}/{id}`. The server gates the rule with
`tests/agent-route-nouns.test.php`, which fails when a literal segment of
an `/agent/v1/` path names a class in `Route::$validClasses`.

**`/agent/v1/` is the agent surface; `/agent/` without `/v1/` is the admin
surface, and the two have different trust boundaries.** The agent surface
is gated by the client certificate (or, for enroll, by nothing but the
claim itself) and answers only about the caller's own host. The admin
surface (`/agent/enrollments`, `/agent/enrollment/{id}/{action}`,
`/agent/tokens`, `/agent/token`) is gated by an API token and the host
permissions, and acts on any host. A route that an admin calls "about
agents" belongs under `/agent/`, never under `/agent/v1/`, however much it
is about agents; the version segment marks the contract the agent binary
is built against, and nothing else.

**What the rule does not cover.** It is a rule about paths on the agent
surface. It does not say anything about the shape of `state` in the poll
answer, which grows a block per capability by design; about the admin
surface, whose routes name nouns because they are about the model; or
about a second protocol version, which is `/agent/v2/` and a new contract,
not a new subject. And a new transport shape is still a decision, not a
loophole: "it needs a different verb" is the start of a design note, not a
license to add the route.

## The two version numbers

`protocol` and `agent_version` both ride the enroll request, both look like
versions, and conflating them makes the `v1` in the path decorative: every
agent release would imply a protocol change. They are different things and
must be allowed to diverge. **Agent 1.4.0 speaking `/agent/v1/` is the
normal case.**

| Number | Lives | On the wire | Stored | Moves when |
|---|---|---|---|---|
| **Protocol** | `enroll.Protocol` (agent), `\FOG\Agent\Enrollment::PROTOCOL` (server) | `protocol` in the enroll request; `protocol` in the poll answer; the `v1` in `/agent/v1/` | nowhere per host | the wire contract changes in a way an existing agent cannot read: a field changes meaning, a required field appears, a status disappears. Currently `1` |
| **Agent version** | `main.Version`, stamped `-X main.Version=` from the release tag | `agent_version` in the enroll and poll requests | `hostAgentVersion`, `aeAgentVersion`, `varchar(50)` | every release, including one that changes no wire byte |

**Neither is derived from the other, and the server never gates behavior on
`agent_version`.** It exists to be reported, and to be compared against a
desired version (design 0015). Anything else the server needs to know about
what an agent can do comes from `protocol`, or from the agent's own declared
capability list — never from parsing a version string. A protocol bump is a
deliberate act with a migration story and a `426`; an agent release is not.

The agent's declared list is `supported` in the poll request: the
capabilities this **binary** implements, as against `capabilities` in the
answer, which is what the **server** is offering this host. The two are
different questions and the server has only ever been able to answer the
second. A server that sees no `supported` key is talking to an agent built
before the key existed.
# Target-based Windows directory operations

The FOG AD Join/Rejoin enhancement requires the server to support both
`directory-join-target-v1` and
`directory-task-operations-v1`. `GET /agent/v1/enroll` advertises these tokens in
`X-FOG-Agent-Features`, separated by commas or whitespace. Additional tokens
are allowed; substrings are not capabilities. Trusted HTTPS and the existing
certificate principal remain required. Unreachable/temporarily unavailable
and reachable-but-unsupported servers are distinct errors, both fail closed.
No exception for AD-disabled hosts is defined for an older server.

The Windows startup path checks a due local update rollback before performing
network feature or identity checks. A failed probe cannot suppress that
deadline. A successful feature probe is not a successful authenticated poll
and does not clear probation.

Before normal polling the agent checks its live SMBIOS/MAC identity through
`POST /agent/v1/identity/check`. An explicit mismatch rotates the local key
using existing Enrollment; ambiguity or failed checks stop normal work.
Unresolved directory markers are retained. A verified marker belonging to the
old principal is archived byte-for-byte during explicit identity rotation.

Windows polls declare both features and a read-only `directory_attempt`
summary of the existing local native marker. This summary is not persisted as
a new classification; it prevents server OU writes while a local operation is
uncertain, even when the server has no matching operation record. The server
requests a revision-bound directory observation: current and pending names,
domain, role, boot, DC reachability and health. A fresh unconsumed completed
Deploy triggers one target Join/Rebind even when the machine is healthy and
already has the desired name. Enrollment alone does not trigger a mutation.
A safe normal rename uses the existing native implementation;
name reassignment, an existing Target or an authorized restore may require
target rebind. No source AD GUID/SID is required or stored on the v2 path.

Plans use `version: 2`, an attempt ID, Host ID, configuration revision,
expected names, domain/DC, `task_id` (zero for non-Deploy operations), and operation
`rename`, `rebind`, or task-bound Workgroup `join`. Existing targets
are bound to confirmed GUID/SID; successful absence and account-creation
permission are required for create. Creation defaults ON; explicit OFF is
preserved. LDAP errors never mean account absence.

`POST /agent/v1/directory/rejoin/start` atomically claims the current plan
before returning the existing join credential. The agent reserves its local
marker before claiming, then persists `may_have_run` before native dispatch.
Task eligibility is rechecked and its high-water consumed with the claim.
Existing rebind uses `0x421`; create uses `0x20423`. Task-bound Workgroup Join
uses the established Windows Join/reuse implementation through the same
claim and marker, preventing a second Rebind for that Deploy. Join without a
Deploy retains the ordinary provider and cooldown. Results echo `task_id` on the existing
directory result contract. Native failure or unknown outcome never silently
falls back to Repair, unjoin or an old-account rename.

The existing reboot coordinator performs the required restart once. The agent
then verifies name/domain/boot/health; the server rechecks the target object
before verified. A later same-name recovery requires a new completed Deploy
or explicit administrator authorization, not a negative health result alone.
Legacy v1 markers remain readable for review but cannot start or replay a new
operation, even when presented with a new plan.

Successful user online logon and saved Netlogon health are separate evidence.
Transient PDC1311 observations remain unresolved; TC status0 alone is not a
health override. This extension does not implement Sysprep/generalization,
change SID, or broaden Microsoft's support policy for Windows cloning.
