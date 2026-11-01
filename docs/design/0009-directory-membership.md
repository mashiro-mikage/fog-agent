# 0009: Directory membership — placement is a directory operation

Status: §3, §4, §5, §7 SHIPPED 2026-09-04. §6 SHIPPED 2026-09-04 (agent
`internal/provider/directoryjoin`, server `FOG\Agent\DirectoryJoin`, schema
428). §6's v2 — offline domain join — remains deferred.

Proven against a real domain controller on 2026-09-04, both platforms, on
throwaway lab machines: a Linux host joined `fogad.lab` with adcli and a
Windows 11 host with `NetJoinDomain`, each using the credential the server
sent and a service account delegated on one OU rather than a domain admin;
each then reported its membership, the server stopped sending the credential,
and §5 placed the object it had just created. The Windows report carries
every field — NetBIOS name, computer DN from the machine's own secure channel,
machine account, site — where Linux carries the domain and machine account
only, exactly as §3 predicted.

One measurement worth keeping: on the freshly joined Windows host, the first
`Gather()` after the join took five minutes to return, because the DN and site
lookups are network calls to a domain controller and the lab reaches its DC
through a NAT hop. They are not slow on a healthy LAN, but they are unbounded,
and they run inside the poll. Not fixed here — Go cannot cancel a blocked
syscall, so a timeout would leak the goroutine rather than free it — but it is
the reason a fact collector should never be assumed cheap.

FOG's Active Directory support is the `hostname` capability's other half: the
same legacy module renames the machine and joins it to a domain, and design
0001 §7 carried the rename across to the agent while leaving the join behind.
This document picks up the join, and changes the model while doing it.

The short version: **membership** is something only the machine can change,
and **placement** is something only the directory can. Today FOG asks the
machine to do both, which is why it cannot do the second one at all.

## 1. What is there today

Seven columns on `hosts`, added in the initial schema and extended twice
(`commons/schema.php:159-163`, `:1872`, `:2855`):

```
hostUseAD  hostADDomain  hostADOU  hostADUser  hostADPass
hostADPassLegacy  hostProductKey
```

Four globals seed them at registration — `FOG_AD_DEFAULT_DOMAINNAME`,
`FOG_AD_DEFAULT_OU`, `FOG_AD_DEFAULT_USER`, `FOG_AD_DEFAULT_PASSWORD`
(`schema.php:725-734`) — plus `FOG_AES_ADPASS_ENCRYPT_KEY` for the password
at rest. `Boot/Registration.php:316-379` applies them to a newly registered
host, and the `ou` plugin, when installed, overwrites `ADOU` on check-in from
an OU association (`lib/plugins/ou/src/Hooks/OUChangeItems.php:103`).

The server hands all of it to the client. `Client/HostnameChanger.php:42-56`
decrypts `ADPass` and `:76` puts the plaintext in the JSON; `Router/Route.php`
`:7169-7192` does the same for the host API. The client is
`Modules/HostnameChanger/` in fog-client, and `WindowsHostName.cs` is where
the interesting part is.

### 1.1 The OU is write-once, and nothing says so

`RegisterComputer()` opens like this
(`Modules/HostnameChanger/Windows/WindowsHostName.cs:222`):

```csharp
// Check if the host is already part of the set domain by checking server IPs
if (IsJoinedToDomain(msg.ADDom))
{
    Log.Entry(Name, "Host already joined to target domain");
    return true;
}
```

`IsJoinedToDomain` compares the *domain*, and it compares it by resolving both
names to IP addresses and intersecting the sets (`:203-220`). **The OU is
never compared to anything.** `msg.ADOU` is read exactly once, as the
`lpAccountOU` argument to `NetJoinDomain` (`:50-52`) — that is, at the moment
of the initial join and never again.

So editing a host's OU in FOG and waiting does nothing, forever, with no error
and one log line saying the host is already joined. There is no OU move in
FOG today: not a bad one, none. The admin workaround is to clear the AD
checkbox, let the client unjoin, then re-check it with the new OU — and that
path runs `NetUnjoinDomain(..., UnJoinOptions.NetsetupAccountDelete)`
(`:277`), then rejoins with `NETSETUP_ACCT_CREATE`.

That round trip is not free, and the cost lands on the *directory object*
rather than on FOG. The rejoin resets the computer account password
unconditionally; where the old object is disabled or removed and a new one is
created, the machine gets a **new SID**. Everything keyed to the object goes
with it: security-group memberships (so group-targeted GPOs and group-based
share ACLs stop applying), BitLocker recovery keys escrowed on the object,
the LAPS password, any machine certificate issued to that account, and any
`msDS-*` attribute someone set. Two reboots, both forced
(`Power.Restart(...)` at `:254` and `:281`).

*Judgment, from Microsoft's documentation rather than from the code:
`NETSETUP_ACCT_DELETE` is documented as disabling the account on unjoin, not
deleting it, and Microsoft marks the flag as not recommended. The
consequences above hold either way, because they follow from the rejoin, not
from the flag.*

### 1.2 The join credential is on every machine

`ADPass` reaches every managed client in plaintext, on every check-in, for the
entire life of the host — not only when a join is pending. It sits in the
client's received configuration.

`HostnameChanger.cs:71` also writes it to the client's log:

```csharp
Log.Debug(Name, "   ADPW  :" + msg.ADPass);
```

*Not verified: whether Zazzles' default log level lets `Log.Debug` reach disk.
`Log` lives in a compiled DLL in `libs/`, so I could not read the gate. The
call site is real regardless, and a support request that says "turn on debug
logging" turns it into a file.*

A domain-join account is not a low-value credential. It can create computer
objects in the directory, and a credential distributed to every workstation is
recoverable by anyone with local administrator rights on any one of them.
FOG's encryption at rest (`FOG_AES_ADPASS_ENCRYPT_KEY`) protects the database
row, and the server decrypts before sending, so it protects nothing on the
wire or on the endpoint.

### 1.3 Nothing records what is actually true

`hosts` stores what an admin *asked for*. No column anywhere records what
domain a machine is actually in, what OU its object is actually in, or when
FOG last knew. So the question an estate owner actually has — *which of my
machines are not where I think they are* — has no answer, and FOG has never
been able to give one. That is the reportability half of this document, and
it is the half that survives even if every other proposal here is rejected.

## 2. The model: two facts with two different owners

| | who can change it | how |
|---|---|---|
| **Membership** — is this machine in domain X | only the machine | it must establish a secure channel; a credential or a provisioning blob has to reach it |
| **Placement** — which container holds the computer object | only the directory | one LDAP Modify DN against the object |

Today FOG routes both through the machine, which is why placement is broken:
the machine has no primitive for "move my object", only "join", so the only
way to express a move through a client is to un-be a member and be one again.

Splitting them makes the OU move a `ldap_rename()` on the server against the
computer object's DN, with a new parent DN. No client involvement, no reboot,
no re-join, no credential on the endpoint, and the object keeps its SID, its
password, its group memberships and everything escrowed on it. The machine
does not need to be powered on.

It is also the only version that works on more than one platform. A
Linux host joined with `adcli`/`sssd` and a Windows host joined with
`NetJoinDomain` have computer objects in the same directory, and a server-side
Modify DN moves both identically. The client-side move never had that
property — it would have needed a distinct destructive dance per OS.

### Why not have the agent do the LDAP move

Considered and rejected. It would need LDAP write rights on the endpoint,
which means a directory-write credential on every machine — a strictly worse
version of §1.2. The machine also has no reason to know its own DN.

### Why not leave the OU alone and document it as unsupported

That is effectively today's behavior, and it is defensible on the grounds that
FOG is an imaging tool. But FOG already collects the OU in the host form, the
group form, the registration defaults and a dedicated plugin, so the estate
already believes FOG manages it. A field that is collected in four places and
honored in none is worse than either supporting it or removing it.

## 3. What the agent reports

A `directory` facts block, gated and hash-compared exactly like `inventory`
(0006 §2) — it changes rarely, so it rides a hash and a `want_directory`
override rather than going up on every poll.

```json
"directory": {
  "joined": true,
  "kind": "ad",
  "domain": "corp.example.com",
  "netbios": "CORP",
  "computer_dn": "CN=WS-014,OU=Sales,OU=Workstations,DC=corp,DC=example,DC=com",
  "machine_account": "WS-014$",
  "site": "HQ"
}
```

No `checked_at` in the block. The server stamps `hdCheckedAt` when it
receives one, because a timestamp inside a hash-gated block changes the hash
every time the collector runs and would resend an unchanged answer forever —
defeating the only thing the gate is for.

`kind` is `ad`, `entra`, `workgroup` or `none`; a field the platform cannot
answer is omitted rather than guessed, and `joined:false` with `kind:workgroup`
is a real answer, not a collection failure. As everywhere else in 0006, the
collector returns `(T, bool)` and a false bool means "no collector ran here",
never an empty struct.

- **Windows**: `NetGetJoinInformation` for membership and NetBIOS name,
  `Win32_ComputerSystem` for the DNS domain, the computer object's
  `distinguishedName` via ADSI/LDAP over the machine's own secure channel (no
  credential needed — the machine account can read its own object),
  `dsregcmd /status` to distinguish Entra-joined from AD-joined.
- **Linux**: `realm list` where realmd is present, then the host keytab
  (`/etc/krb5.keytab`), then the sssd domain configuration. The keytab is
  second because it is the only one of the three that is *evidence*: a
  machine account principal (`WS-014$@CORP.EXAMPLE.COM`) is a key only a
  domain controller could have issued, where sssd.conf records what someone
  configured and might never have completed. It is also the only probe that
  sees the agent's OWN join — §6 joins with `adcli`, and adcli configures no
  name-service stack at all, so a machine this agent joined has no realmd
  entry and no sssd.conf. Proven the hard way in the lab on 2026-09-04: the
  join succeeded, `adcli testjoin` validated it, and the agent reported
  `joined=false`, which would have had the server re-send the join
  credential every hour for ever — the exact behavior §6 exists to prevent.
- **macOS**: `dsconfigad -show`. Lower priority.

This block alone makes drift reportable and requires no new credential
anywhere, which is why it is §3 and the rest is later.

## 4. The table

`hostDirectory`, one row per host, 1:1, following `inventory`'s precedent that
observed facts live beside the host record rather than inside it. Desired
state stays on `hosts` where it already is — this table never duplicates it,
so there is exactly one place to edit an intent and one place to read an
observation.

```
hdID  hdHostID  hdJoined  hdKind  hdDomain  hdNetbios  hdComputerDN
hdMachineAccount  hdSite  hdObservedAt
```

`hdComputerDN` is the load-bearing column: it is what a server-side Modify DN
needs, and having the agent report it means the server does not have to search
the directory for the object by name and guess between duplicates.

`hdObservedAt` is when this membership was last **reported**, not when it was
last confirmed true. The agent hash-gates the block, so an unchanged
membership is never sent and a column called `hdCheckedAt` would be claiming a
freshness nobody checked. *Is this still true* is answered by the host's own
`hostAgentCheckin`, which the report shows in its own column beside it.

Placement columns (`hdMovedAt`, `hdMoveError`, recording a Modify DN that
failed for want of rights or a missing OU) belong with §5 and are not in the
v1 table. Adding them is one more schema step when §5 is decided; carrying
them now would be shipping the shape of a feature nobody has approved.

## 5. Placement, server side

The server compares `hostADOU` against `hdComputerDN`'s parent. On a
difference it calls `ldap_rename()` with the same RDN and the new parent DN,
and records the DN the object now has — a true return from `ldap_rename` is
the directory confirming the object is there, so that is an observation, not
an assumption. Leaving the old DN in place would make FOG move an object that
has already moved, once per poll, forever.

Built as `FOG\Agent\DirectoryPlacement` over `FOG\Net\FOGLdap`. Two things
about it read backwards, and both were found by building it:

**It hangs off the poll, not off the fact report.** The obvious wiring is to
place after storing a report, since that is when the observation changes. But
a report only happens when the *machine's* membership moved, and the other
source of drift — the whole reason this document exists — is an admin editing
the host's OU, which no machine will ever report. Hanging placement off the
report would mean an edited OU never takes effect until the host happens to
change domains: §1.1's bug, arrived at from the other direction.

**`ouDrifted()` is not the gate.** It answers "no drift" when the observed
container is unknown, deliberately (§7: a report full of rows nobody can act
on is a report nobody reads). But no Linux join tool exposes a DN, so gating
on it excludes every Linux host from placement forever — and looks exactly
like the feature not working. A host that cannot say where it is gets asked
about at the directory instead, by machine account name. The directory is the
authority on where its own objects live, and it can answer for a machine that
is switched off, which is the point of §2. That costs a bind, so it is bounded
to hourly per host by `hdPlacementAt`; a host that *does* report its DN and is
where it belongs is compared for free on every poll and never opens a
connection.

`hdPlacementAt` is stamped on every consultation, successful or not, because
it is what that cooldown reads. It is named for the attempt: `hdMovedAt` would
have claimed a move on every occasion nothing happened, the same defect
`hdObservedAt` was renamed to avoid.

Off unless both the switch and a server are configured. This writes to
somebody's directory, so it must never begin working because they upgraded.

`php-ldap` is a hard dependency of a FOG install, not an optional extra —
every supported distro's package list carries it (`lib/redhat/config.sh:23`,
`lib/ubuntu/config.sh:46`) and the installer uncomments `extension=ldap` in
`php.ini` (`lib/common/functions.sh:12073`). So this needs no availability
check and no degraded path.

**This needs a credential FOG does not have today**: an account with rights to
move computer objects. That is a new privileged secret in FOG and it is the
one open question in this document — see §8.

## 6. Membership, agent side

A `directory` desired-state capability alongside `hostname`, returning the
same `provider.Result` vocabulary. It only ever joins; it never unjoins and
never re-joins a machine that is already in the target domain. Leaving a
domain stays a deliberate, separately-expressed act, because §1.1's cost is
real and it must never be a side effect of an edit.

The join credential changes shape:

- Sent **only** in the poll response for a host that is not joined and has a
  desired domain — never as ambient configuration, and never to a host that is
  already where it should be. A joined estate carries no join credential at
  all, which is most of the estate most of the time.
- Over the mutually-authenticated channel of 0002, bound one certificate to
  one host row.
- Held in memory only. Never written to `config.json`, never logged at any
  level, zeroed after the attempt. 0005 already locks the state directory to
  SYSTEM and Administrators; this simply never goes there.

That is a large reduction against §1.2 and needs nothing new from the
directory. It is still a reusable credential on an endpoint for the duration
of one join, which is why it is v1 rather than the destination.

**v2 is offline domain join.** The server already needs LDAP write rights for
§5; with them it can pre-create the computer account in the correct OU and
hand the agent a provisioning blob, which the agent consumes with
`djoin /requestODJ`. The blob is single-use and specific to one machine and
one account, so no reusable credential ever leaves the server, and the machine
lands in the right OU on the first join with no move needed. Samba's
`net offlinejoin provision` produces the blob from Linux. Deferred, not
dismissed: it needs verification against a real domain controller, and the
protocol shape (a base64 blob in place of a credential) is a small change to
make later.

### 6.1 What a Windows join changes besides membership

Worth stating because the lab proof walked into it and any site joining
Windows hosts through FOG will too: a successful join moves the machine's
network profile from Private to DomainAuthenticated, and **inbound firewall
rules scoped to the old profile stop applying**. On the lab host, RDP stayed
reachable and SSH and ping did not, which looks precisely like the machine
having fallen off the network — while the agent itself kept polling, because
the agent's traffic is outbound and nothing blocks that.

Two things follow. The agent is unaffected, so FOG does not lose the host and
this never becomes an emergency. And the machine may nonetheless become
unreachable by whatever the admin was using to reach it, which is the kind of
thing that must be said in the documentation for the join, not discovered.
The agent must not "fix" this: opening a firewall the site closed is not
something a management agent gets to do as a side effect of a join.

## 7. Reporting

A `Directory Membership` report under Lists, gated on `host` like
`User Sessions` (0008), one row per host with `useAD` set:

| Host | Desired domain | Observed domain | Desired OU | Observed OU | Drift | Last checked |

"Drift" is the column that does not exist today in any form. A host whose
observed OU differs from its desired OU is exactly the thing §1.1 silently
never fixed, and after §5 it is also the work queue for the fixer.

## 8. The credential — decided

Everything in §3, §4 and §7 is reporting: no new credential, no new rights, no
change to what any machine does. Everything in §5 and §6 turns FOG into a
directory *writer*, and §5 in particular means FOG holds an account that can
move computer objects.

That was an access-control change, so it went to Tom rather than being
assumed. **Decided 2026-09-04: option 1, a FOG-level directory service
account.** The options as they were put:

1. **A FOG-level directory service account** *(chosen)*, stored like the LDAP
   plugin's existing bind credential, used only for placement. One secret,
   held in one place, never distributed. Rights can be delegated narrowly in
   AD to "move computer objects within this subtree", which is a normal
   delegation.
2. **Reuse the per-host `hostADUser`/`hostADPass`** for the move. No new
   secret, but it conflates the join account with the placement account and
   keeps the credential-per-host model this document is trying to shrink.
3. **Ship §3/§4/§7 only.** Reporting and drift detection, no writes. Strictly
   an improvement over today, and it is the part that carries no new risk.

The narrow-delegation claim in option 1 is the load-bearing one, so it was
tested rather than asserted, against a Samba AD DC standing in for a customer
forest. A service account granted create-child and delete-child of computer
objects on `OU=Workstations` alone, and nothing else:

```
FOGLdap::connect  ok (ldaps, certificate verified)
FOGLdap::findComputer  CN=WS-014,OU=Engineering,OU=Workstations,DC=fogad,DC=lab

FOGLdap::moveTo  -> OU=Sales,OU=Workstations,DC=fogad,DC=lab
  ok, now at CN=WS-014,OU=Sales,OU=Workstations,DC=fogad,DC=lab

FOGLdap::moveTo  -> CN=Computers,DC=fogad,DC=lab (outside the delegation)
  refused, as it must be: Insufficient access
  still at CN=WS-014,OU=Sales,OU=Workstations,DC=fogad,DC=lab
```

The second half is the half that matters. An account that could move a
computer object anywhere in the forest could hide a machine somewhere nobody
monitors; one that is refused at the edge of its subtree cannot. Re-runnable:
`scripts/background_scripts/prove_fogldap_moves_a_computer.php`, which drives
the shipped `FOGLdap` rather than raw `ldap_*` calls, so it re-proves the code
path and not just the idea.

Settings, all created off and empty by schema 424: `FOG_DIRECTORY_LDAP_URI`,
`FOG_DIRECTORY_BIND_DN`, `FOG_DIRECTORY_BIND_PASSWORD` (encrypted, read
through the same probe the LDAP plugin uses), `FOG_DIRECTORY_BASE_DN`,
`FOG_DIRECTORY_CA_CERT`, and `FOG_DIRECTORY_PLACEMENT_ENABLED`.

## 9. What this is not

- **Not Entra / Azure AD join.** The facts block reports `kind: entra` so an
  Entra-joined machine is not mis-reported as unjoined, but joining one is out
  of scope: it is a device-registration flow, not an LDAP one.
- **Not GPO, not group membership, not any other directory write.** One
  object, one parent, one operation.
- **Not product-key activation.** `hostProductKey` rides the same legacy
  module by historical accident and has nothing to do with directories. It
  belongs with `hostname` or on its own; either way, not here. Design 0016
  gives it its own capability.
- **Not a replacement for `hostname`.** The rename stays where 0001 §7 put
  it. A rename of a joined machine has its own directory consequences and is
  a separate problem: design 0017.
- **Not an unjoin.** See §6.
# Target-based Windows extension

See `protocol-v1.md` for the paired server/agent contract. Existing Workgroup
Join and safe ordinary domain rename remain in use. Rebind selects a confirmed
target account instead of repairing or renaming a reassigned old account.
Source GUID/SID management is not part of this contract. Identity ambiguity,
unresolved legacy markers and unknown native results stop automatic work.
The existing coordinator handles the restart and post-boot verification.

The FOG AD Join/Rejoin enhancement uses
`directory-task-operations-v1` for Target-bound operations. It stores
no Clone classification. A completed Deploy is the one-shot authority even for
a healthy self-restore. Task-bound Workgroup Join participates in the same
claim/marker; ordinary Workgroup Join without a Deploy retains its existing
policy. Enrollment or server migration alone does not require Rebind.
