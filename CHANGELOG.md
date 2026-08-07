# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `agentwall verify-capture --agent <id>`, which proves one declared agent's traffic actually
  passes through AgentWall instead of assuming it because the configuration looks right. It binds
  a single-use canary on an ephemeral loopback port with a 256-bit token in its path, drives the
  fetch (`--command '<cmd>'`, or interactively by printing the URL and waiting), then asserts
  three things and reports each separately: a record for that exact request is in the chain, the
  record binds it to the named agent AND AT WHICH TIER, and the canary was not reached directly.
  The third assertion is the reason the command exists. A request that arrives at the canary with
  no matching chain record is an agent that reached the network without passing through, and a
  check that looked only for a chain record would report "captured" while half an agent's traffic
  went around the proxy. The bypass is named, not merely counted: the pid that opened the
  connection is resolved through /proc and compared against the pid listening on the proxy port,
  so the report says which process escaped. That comparison is three-valued, because attribution
  is best-effort and treating "could not tell" as "not the proxy" would fail every correctly
  captured agent on a host where AgentWall runs as another uid. Binding tier is always printed:
  "captured, bound by comm only" is a materially weaker statement than "captured, bound by
  credential", and an agent configured for a credential that binds by comm is flagged as weaker
  than configured. Exit 0 captured, 1 not captured or bypassed, 2 could not be completed. See
  docs/verify-capture.md, which states what the command does not prove: it proves the path the
  agent used during the check, not that no other egress path exists.
  `verify-capture` also reads the `NO_PROXY` its fetch will inherit and refuses to call an
  exempted canary a bypass. `NO_PROXY=localhost,127.0.0.1,::1` is a reasonable-looking line that
  makes a loopback canary reached directly BY CONSTRUCTION, and reporting that as a bypass would
  accuse an operator of a hole their own configuration deliberately opened. The outcome is
  inconclusive with exit 2, naming the entry and the fix, and saying plainly what the entry
  costs: every address in `NO_PROXY` is one the agent is TOLD to reach without AgentWall. The
  match is graded rather than binary, from measurement: curl 8.5.0, python requests 2.31.0 and
  node 24 under `NODE_USE_ENV_PROXY` all compare a `:port` in an entry, so `127.0.0.1:3000` is
  inert for all three and does not suppress a verdict, while a bare host or `*` does. An earlier
  draft of this feature asserted the opposite about curl from memory and was wrong; two
  independent rigs now agree. Go was not tested and nothing claims anything about it. The whole
  list is walked across both variable spellings before answering, so a narrow entry cannot mask
  a broader one later in the same list.
- `src/proxy/socket-attribution.ts`: the /proc/net/tcp to pid resolution the forward proxy has
  always used, extracted so `verify-capture` can identify the far end of a canary hit through the
  same code rather than a second parser free to drift from it. Adds `listenerPids(port)`, which
  returns every pid holding a LISTEN socket on a port as a set, because a dual-stack bind and a
  pre-forking server both produce more than one and picking the first would compare a canary's
  peer against the wrong half.
- A capture section in `agentwall doctor`, per declared agent: when it was last seen and at which
  binding tier, its request and byte counts against its budget in the current window, and the
  weakest binding tier anywhere in the fleet. Loudest of all, and first in the section, is
  undeclared egress recorded since the last run, because rising undeclared traffic is what an
  escaping agent and a broken identity binding both look like. An agent declared but never seen
  renders as `DECLARED, NEVER SEEN` rather than a row of zeros: "never started" and "seen four
  minutes ago and idle" are different states, and a counter table shows them identically.
  Everything comes off the chain and the config, with no background collector and no call to
  the running service, because the moment you most want this answer is the moment that process
  is suspect. `--audit` selects the chain and `--json` prints the whole report.
- Three verdicts from `agentwall doctor`, not two: 0 clear, 1 failed, 2 INCONCLUSIVE. Undeclared
  egress that reached the network is only called an escape when the record itself says
  `fleet.unmatched: deny` was in force under an enforcing mode, which is the combination
  `src/runtime/enforcement.ts` refuses before opening an upstream socket. Under `unmatched:
  global` (the default) or `enforcement.mode: monitor` (where every adoption starts), the same
  traffic is what the configuration prescribes, so doctor reports INCONCLUSIVE and names the
  setting to change rather than accusing an operator of a breach their own defaults arranged.
  A refused attempt never fails a run. Egress records now carry `fleetUnmatched` so the verdict
  is read from the record rather than from a config file that may have been edited since;
  records predating the field are judged by the current config and the report says so.
- `strongestBindingTier` and `weakestBindingTier` on the fleet registry, derived from the same
  rule the resolver indexes by. A declaration naming both a credential and a comm is reported at
  its comm strength: `resolve()` falls through to comm when no credential is presented, so any
  process claiming that name binds without the secret, and reporting "credential" there would
  describe a property the declaration does not have.
- Content inspection on the forward proxy's plaintext HTTP path. The DLP engine, the injection
  scanner, and the decoy tripwires all existed and were wired to zero proxied bytes: no call site
  under `src/proxy/` reached any of them, and `scanForDecoys` had no call site on any request path
  at all. An http exchange now has its request path, request headers, request body, response
  headers, and response body scanned, and a detection blocks with a 403 and
  `X-Agentwall-Block-Reason` under the existing guarded and strict semantics while monitor reports
  what they would have done. Response bodies are inspected as well as requests, because a poisoned
  tool result arriving in an answer is the shape a control that watches only egress never sees.
  Four rules and four detections back it: `net:deny-proxy-request-secret`,
  `net:deny-proxy-request-injection`, `net:deny-proxy-response-injection`, and
  `net:flag-proxy-response-secret`, which records rather than refuses because an agent reading a
  credential it is entitled to is the common case. A decoy hit is refused by the runtime rather
  than by a rule, so replacing the rule set cannot switch it off.
- `EgressAttempt` carries the request path, headers, and one buffered body, all optional because a
  CONNECT tunnel genuinely has none of them and must not be made to fabricate them. `buildContext`
  now puts the path into the synthesised URL and into its own payload field; it previously
  synthesised `scheme://host:port` with nothing after the authority, so a rule written against a
  URL path matched nothing and said nothing about why.
- `bodyVisibility` on every proxy record, reading `tunneled`, `unread`, `stream`, `partial`, or
  `plaintext`. It exists to remove one ambiguity: a row with no findings can mean "nothing was
  there" or "we could not look", and the second reads exactly like the first to anyone skimming.
  Findings are namespaced by direction and carry the class and the offset of each match, never the
  matched value; the recorded path has its query string removed for the same reason, since
  `?api_key=...` is one of the shapes the scan exists to catch.
- An OpenTimestamps proof parser, `src/audit/ots-proof.ts`, implementing the proof grammar of
  `docs/audit-format.md`. It is bounded against hostile input with caps on argument size, total
  size, fork depth, operation count, and working message length, because the file being verified is
  attacker-influenced by definition. RIPEMD-160 and Keccak-256 operations are declined rather than
  evaluated, matching the independent Go verifier.
- A read-only evidence viewer at `/evidence`, with the same report as JSON at `/api/evidence`. It
  projects the existing audit chain rather than recording anything new: a per-session scorecard of
  what an agent did, what was allowed, denied, sent to approval or redacted, which detections fired
  and which rules matched; the `chained`, `linked` and `anchored` layers shown inline with the state
  and the verdict `agentwall verify` prints side by side; a signed receipt timeline naming the
  highest record index each anchor demonstrably commits to, re-derived from disk rather than read
  off the record; and the offline verify command printed on the page, because a console over signed
  evidence must not be the root of trust for it. Read only is structural: only `GET` handlers
  exist, every mutating method returns `405`, and the page serves no script. A pending anchor
  renders as `pending`, and an anchor whose record claims `confirmed` while its proof carries only
  a calendar attestation also renders as `pending` with the overclaim named, which is stricter than
  the layer counter and never looser. Layers with no supporting evidence for a span render
  `absent`, so a session still in the unsealed live file is not shown as covered by the rotation
  manifest. One request reads at most 100,000 records and skips a file above 64 MB, stating the cap
  on the page when it bites. Behind the operator bearer token like every other non-health route;
  `AGENTWALL_ALLOW_LOOPBACK_DEV=1` is what makes it openable in a browser.
- Read-only multi-host evidence aggregation at `/evidence/fleet`, with the same report as JSON at
  `/api/evidence/fleet` and one page per host. It is the single-host viewer one level up: each
  host's chain is read from a path and verified independently by the same `runVerify()`, on its
  own bytes. The chains are deliberately NOT merged: N hosts produce N independently anchored
  chains, merging them needs a total order across hosts, and nothing an auditor asks requires one.
  Each host's page prints all four independent verifier implementations against that host's own
  file, because reproducing the aggregator's verdict without trusting the aggregator is worth more
  across a fleet than on one laptop. The per-agent rollup answers which agents ran, on which hosts,
  in which window, what the identity claim rests on, which allowlist judged it, what each attempted
  by destination, what refused it by rule id, and whether credential material was seen in flight
  and whether it was redacted; the proxy plane records a class and never a value and never rewrites
  a body, and the page says so rather than letting a detection read like a removal. Host sources
  come from a file named by `AGENTWALL_FLEET_EVIDENCE`, re-read per request, with a required
  `staleAfterSeconds`; a malformed sources file renders no host at all rather than a fleet quietly
  missing whichever entry had the typo. Read only is structural and has one mechanism more than the
  single-host viewer: only `GET` handlers exist, every mutating method returns `405`, the page
  serves no script, and nothing here opens a socket to any host or holds a credential on one.
- Failure semantics on the fleet view, stated because "no findings" and "could not look" must never
  render alike. Five host states: `verified`, `broken`, `stale`, `empty`, `unreachable`. An
  unreachable host shows its last-seen time and NO layer verdict, because a verdict over a file
  that could not be opened would be invented and would be either a false clean or a false alarm.
  The aggregate has three states and cannot say clean while anything is unread: any unreachable,
  stale, or empty host makes it `incomplete`. A chain nobody has anchored off-box is reclassified
  from the anchored layer's `FAIL` into a counted coverage gap rather than a break, with the layer
  still shown verbatim beside the CLI's verdict, because an absence of external evidence is not
  external evidence that disagrees and painting every unanchored deployment as tampered with
  teaches an operator to ignore red.
- Coverage gaps as first-class content on both fleet pages, separating three things that are
  routinely conflated: the limit, which is a property of the controls; whether it can be counted
  at all; and the count in this evidence, which reads `unmeasured` rather than `0` when there was
  no population. Eleven rows, including https bodies relayed unread without opt-in interception,
  the 256 KiB inspection cap, the padding evasion past it and DNS to a named resolver, both of
  which are permanently unmeasurable and say so instead of reading zero, streams passed through
  uninspected, deliberate interception bypass, credential material recorded but never removed from
  a proxied body, monitor-mode allows that blocked nothing, the transparent path carrying no fleet
  identity, chains with no off-box anchor, and completeness.
- `EvidenceRecord` carries two named sub-objects read back from the metadata the writers already
  emit: the fleet attribution (`agentLabel`, `agentMatchedOn`, `agentDeclared`,
  `egressAllowlistSource`) and the proxied-connection annotation (destination, scheme, enforcement
  mode, transport mode, `bodyVisibility`, whether a body was read only to the cap, and the classes
  of secret the scan named). Named keys, never the metadata block. Both the prefixed spelling the
  plaintext proxy produces and the unprefixed spelling the interception path produces are read: the
  interception path files one record per inner exchange and never folds two passes together, so a
  reader that knew only the prefixed form would report a decrypted, scanned https body as carrying
  no findings, which inverts the meaning of the coverage table.

### Changed
- The bundled verifier returns the same verdict as the independent Go verifier on every case in the
  conformance corpus, and the harness declares no divergences. Two parts of the report moved. The
  `anchored` layer judges an anchor record by the evidence instead of by what the record says about
  itself: it recomputes each record's digest from the checkpoint the record embeds and reports
  `digest-mismatch` when they differ, requires non-empty proof bytes behind any submission that
  reached a calendar and reports `proof-missing` when they are absent, and parses the proof against
  the submitted digest, reporting `proof-parse-error` when the container does not parse. An anchor
  claiming `confirmed` with no proof file behind it fails the layer. A submission recorded with an
  `error` is exempt: it never reached a calendar, so it has no proof to point at and is already
  counted as failed. The `chained` layer reports a partial final line as `torn-tail` and does not
  fail over it, because a hard kill mid-append leaves exactly one and calling that tampering would
  cry wolf on every crash; a line that does not parse anywhere else, or one that carries its
  terminator, stays a fatal failure.
- `agentwall anchor` parses a calendar response before keeping it, and treats one that does not parse
  as a submission failure rather than writing it as a proof. A broken or hostile answer therefore
  leaves a recorded gap instead of a file that a later verify reports as corrupt evidence.

### Removed
- Capability tickets. `/evaluate` minted an HMAC-signed ticket, `capabilityTicket`, and nothing in
  the product ever presented one back: the verifier function had exactly one caller, its own test.
  The signing key was generated per process, so a ticket could not be checked by anything but the
  process that issued it and did not survive a restart. A signed token nobody checks reads to a
  reviewer as an authorization control and is not one, so the minting is gone rather than given an
  endpoint no client calls. `PolicyEvaluationResponse` no longer carries the field.

### Fixed
- MCP inventory checks now validate complete tool descriptors, reject malformed pages, and detect
  drift in output schemas, annotations, icons, and metadata.
- Paginated MCP inventory checks now isolate concurrent cursor sequences and deny unknown cursors.
- Persistent MCP baselines now preserve complete descriptors, replace files atomically, and refuse
  an old lock when its owner cannot be proved dead.
- `verify-capture` now uses an argument array without a shell and kills the child process group on
  timeout, so descendants cannot retain its pipes.
- The CLI now reports the real package root and prints one concise error before exit. The public
  console keeps structured failure output visible for operator review.
- A configured audit anchor schedule now starts with the server, logs each result, and stops during
  shutdown.
- `agentwall perimeter install` installs a perimeter. It never did. It handed the ruleset to
  `nft` on standard input as `spawnSync("nft", ["-f", "-"], { input: ruleset })`, and Node does
  not give a child process a pipe for `input`: libuv backs child stdio with a Unix domain
  socket. `nft -f -` resolves to `/dev/stdin`, stats it, accepts neither a socket nor anything
  that is not a regular file or a fifo, and refuses the whole transaction with
  `Not a regular file: "/dev/stdin"`. Every invocation on every host exited 1 and created no
  table. The documented `plan | sudo nft -f -` pipeline was never affected, because a shell pipe
  really is a fifo, and that is why this survived: the tests either asserted on the rendered
  string or checked a file they wrote themselves with `nft --check --file`, so nothing exercised
  the path an operator runs as root. The ruleset now goes to a `0600` file in a private
  temporary directory which is removed afterwards, and `tests/perimeter-nft.test.ts` asserts the
  argument handed to `nft` is a readable regular file rather than a bare dash.
- Audit records lost to a failing sink no longer read as tampering. The chain state advanced before
  the sinks ran and the sink error was swallowed, so a record that never reached disk still moved
  the chain on, and the next record carried the index jump and broken link of a DELETED record.
  `agentwall verify` reported the same findings for a full partition as for the corpus forgery
  `b3-record-removed`, while the process stayed up and said nothing. The chain now advances only
  after a durable sink accepts the record, so the file stays contiguous across a loss; the refused
  record goes to stderr under `agentwall_audit_dropped` without an integrity block; and the first
  append that succeeds afterwards writes a gap declaration record, which both verifiers report as
  the non-fatal `chain-gap-declared`. `/health` carries the drop counters. See
  [The gap declaration record](docs/audit-format.md#the-gap-declaration-record).
- The audit file sink rolls back an append that ran out of space part way through. A short write
  left a fragment with no terminator, and the next append fused onto that line, so a full disk
  destroyed a record that had been written on top of the one that had not.
- A failed console write no longer terminates the service. With stdout or stderr redirected to a
  regular file, node backs the stream with a synchronous writer whose failure Writable turns into
  an `'error'` event rather than an exception, so the per-sink try/catch never saw it and an
  unhandled event killed the process on the next tick. A partition full enough to stop the audit
  file therefore took down the thing gating egress, on the record after the first one it could not
  write.
- Every surface that reports a version or a Node floor now reads it from `package.json` instead of
  holding its own copy. `GET /health` and the OpenTelemetry instrumentation scope both answered
  `0.1.0` after the manifest had moved to `0.2.0`, so a liveness probe named a release that was
  never cut. `agentwall doctor` compared only the major version against 20, so it green-checked
  Node 20.x and Node 22.0.0 while `engines: >=22.12.0` refuses both at install time, and
  `docs/install.md` still asked for "Node.js 20+" against a changelog that had already raised the
  floor to 22.12.0. The new `src/version.ts` exports `packageVersion`, `nodeFloor`, and
  `meetsNodeFloor`, comparing major, then minor, then patch. The release workflow now fails the
  build when `dist/version.js` or `agentwall --version` disagrees with the tag, so the four
  surfaces cannot silently drift apart again.

## [0.2.0] - 2026-08-05

The first tagged release. It freezes the on-disk evidence format and makes that format
checkable by a program that shares no code with Agentwall.

Upgrade if you care whether the audit log can be quietly rewritten. Before this release the
hash chain was verifiable only by the same TypeScript that wrote it, which means a bug in the
writer was invisible to the reader. Now the format is specified in `docs/audit-format.md`, a
second implementation in Go verifies it, and the two are held against a shared corpus on every
commit. Existing audit files stay verifiable: records written before this release carry no
canonical-form marker and are still accepted through the legacy path.

Nothing about the shipped posture changed. Monitor-first is still the default, and no default
decision, policy file, or enforcement behavior moved in this release.

### Added
- Canonical form `cu1`, recorded in each record's `integrity.canon`. Object keys are ordered by
  UTF-16 code unit rather than locale collation, so a verifier in another language reproduces
  the hash without shipping ICU tables. Records without the marker are hashed under the old
  locale-dependent order and remain verifiable through a fallback path.
- A rotation manifest, `segments.jsonl`, that binds every sealed segment to its own bytes. Each
  entry carries a hash of itself and the final hash of the segment before it, so deleting a
  rotated segment, reordering two of them, or rewriting one after it was sealed is now
  detectable rather than silently invisible.
- Live-tail re-derivation. A checkpoint commits to a prefix of the live file, so the log growing
  after a checkpoint is normal and does not invalidate it, while rewriting any record inside the
  committed prefix fails verification.
- Rejection of records containing duplicate JSON keys. Implementations disagree about which
  value of a repeated member wins, so a duplicate key is a way to hand two readers the same
  bytes and have them reach different conclusions about what was recorded.
- Off-box anchoring wired to the CLI: `agentwall anchor` seals the current segment, signs an
  Ed25519 checkpoint over the composite state, and submits it to OpenTimestamps calendars.
  `agentwall verify` reports the chained, linked, and anchored layers separately and exits
  non-zero unless all three hold.
- An independent verifier, `agentwall-verify`, written in Go against `docs/audit-format.md`
  rather than against our source. It uses the Go standard library and nothing else, so
  `go list -m all` prints one line, and it performs no network access and writes no files.
  Published as binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and
  windows/amd64, attached to the GitHub release alongside `checksums.txt` and
  `SHA256SUMS-verifier.txt`. Only two of those five are statically linked, and the distinction is
  security relevant enough not to round up: `file` reports linux/amd64 and linux/arm64 as
  `statically linked`, while both darwin binaries are Mach-O `DYLDLINK` against
  `/usr/lib/libSystem.B.dylib` and windows/amd64.exe imports the Windows system DLLs, among them
  `kernel32.dll`, `advapi32.dll` and `ws2_32.dll`. Go cannot emit a fully static binary on either
  platform, because libSystem is the only supported syscall interface on macOS and the Windows
  syscall interface is those DLLs. What is true of all five is the property that matters for
  running one: `CGO_ENABLED=0` means no cgo and no third-party runtime, so each binary needs only
  the libraries its own operating system already ships, and never a Go toolchain or a package
  install.
  Five binaries is not five equally convenient installs: macOS and
  Linux have a generated Homebrew formula, `agentwall-verify.rb`, built from those same checksums
  and attached to the release, while Windows has the `.exe` and nothing else, because Homebrew has
  no Windows support. The formula is not yet published to a tap, and Homebrew refuses to install a
  formula that is not in one, so using it means copying it into a local tap first; the three
  commands are in docs/install.md. The formula was installed and `brew test`ed against real
  Homebrew, and passes `brew audit --strict`.
  The builds are reproducible, which is the claim that matters for this artifact specifically:
  `scripts/build-verifier.sh` is both the script the release runs and the script a stranger runs
  to rebuild, and the release fails if the binaries do not rebuild byte-identically from a source
  tree with no `.git`. Reproduction needs the exact Go version that script pins, because a
  different Go emits different bytes.
  Version verification is not uniform across the five, and the difference is worth stating:
  linux/amd64 is verified by execution, since the release runs `--version` on it and fails if the
  output disagrees with the tag. The other four are correct by construction rather than
  version-verified: all five come from one invocation of that script passing one `-ldflags` value,
  and the release additionally confirms statically that each asset embeds the release version
  string. That static check deliberately claims nothing stronger, because a Go binary contains the
  version string whether or not the `-X` stamp resolved. No emulation and no macOS runner are used,
  so `--version` on real darwin or windows hardware is not claimed.
  Note what each download check buys: `sha256sum -c` against a
  `checksums.txt` fetched from the same release page proves the download is intact, and proves
  nothing about whether the release itself is honest, since both files came down the same channel.
  Verifying the SLSA provenance with `slsa-verifier` raises that to "this workflow built it from
  this tag", and rebuilding from source removes us from the chain entirely. Full procedure in
  [docs/install.md](docs/install.md#verify-a-downloaded-verifier-binary).
- A 26 case conformance corpus covering valid evidence, forgeries, and boundary conditions, run
  through both verifiers on every commit. The two agree on all 26 cases and the harness declares
  no divergences. Four cases diverged when the corpus first shipped, each one a place the bundled
  TypeScript verifier accepted evidence the format rejects; they were closed by making the
  bundled verifier check what the anchor record proves rather than what it claims. The harness
  still reports divergence explicitly rather than papering over it, which is how those four were
  found.
- `docs/audit-format.md`, the normative specification. The implementations conform to it, not
  the other way around.
- FloodGuard shield mode control surface in the dashboard.
- FloodGuard per-session temporary override API and operator controls.
- Forward-facing Agentwall logo assets wired into README and public HTML surfaces.
- CLI live-control commands for dashboard status, approval mode, FloodGuard tuning, and direct session pause/resume/terminate actions.
- Approval webhook notifications for queued and resolved manual reviews via `approval.webhookUrl`.

### Changed
- `@repsecure/agentwall` is the intended scoped npm package name and is not public yet. The
  unscoped name `agentwall` on npm belongs to an unrelated project and always has. The installed
  command is still `agentwall`. Registry publication remains a separate approval-gated release action.
- The supported Node floor is 22.12.0, declared in `engines`. Node 20 reached end of life in
  April 2026 and a security tool should not advertise a runtime that stops receiving fixes.
- CLI terminate now requires `--confirm` so hard containment is deliberate instead of one typo away.
- Live-control docs now point to the monitor-first example on port `3015` to avoid false 401/404 debugging on the wrong local service.
- Session control CLI errors now explain how to recover from `Session not found` by seeding a live runtime session first.
- CLI status now shows terminated session counts directly so containment state is visible without flipping back to the dashboard.
- CLI status now surfaces FloodGuard guidance, pressure, hottest-session context, active session-override expiry, the exact live control target, and ready-to-run CLI next moves so operators can tune runtime controls from the terminal.
- CLI top-queue output now includes the queue item's next operator action plus risk/wait summary, which makes shell-first approval triage a lot clearer.
- FloodGuard shell/dashboard operator surfaces now also show the hottest block categories, the top pressured sessions, and the latest live block reason so triage can happen before operators start flipping controls blindly.
- CLI next moves now calm back down with the runtime: once pressure is normal they recommend cleanup actions like `approval-mode auto` and `session-reset` instead of still suggesting a pause on the hottest session.
- CLI status now keeps shield normalization conservative too: it will not suggest `agentwall normal` while paused or terminated sessions still need operator review.
- CLI status suggestions now preserve `--url` or `--config` when the operator targeted a non-default instance, keeping follow-up commands copy-pasteable.
- CLI status no longer suggests `pause` for the hottest session when that session is already paused or otherwise contained, which cuts one more pointless operator step out of shell triage.
- Live-control success output now echoes the resolved Agentwall target too, so shell transcripts stay anchored to the exact instance that was changed.
- Dashboard and CLI active-agent-now counts now drop paused or terminated sessions out of the live tally while still retaining those agents in history, which fixes the misleading "active now" readout after containment.
- Approval queue ordering now prioritizes higher-risk items under pressure.
- Priority Queue approval cards now support one-click approve/deny triage from the operator dashboard.
- The default console now includes a Detection Timeline that merges queue pressure, FloodGuard blocks, and critical runtime events into one operator-first feed.
- The approvals panel now leads with a triage summary so operators immediately see what to review first or what the last decision was.
- Approval rows now surface waiting age, operator attribution, and decision context directly in the table so triage takes less scanning.
- The approvals panel now separates Pending Decisions from Recent Decisions so operators see action items before audit history.
- Critical and high-risk approvals now carry stronger inline priority badges so operators can spot the hottest review items immediately.
- Approve and deny actions from the main approvals panel now prompt for a short operator note instead of writing a generic canned note.
- Main-panel approval actions now show explicit success feedback after a decision is saved so the operator gets immediate confirmation.
- Approval rows now surface matched rule context directly in the panel so operators can see the leading policy trigger without opening drilldown.
- Pending approvals now have an explicit mixed-risk ordering test and panel-side sort to keep critical items pinned before older lower-priority reviews.
- The approvals panel now shows a queue health summary with pending count, critical count, and oldest waiting item before the pending decision list.
- Brand asset docs now point at the actual public asset path.
- Policy and config YAML now parses under the YAML 1.2 core schema on js-yaml 5. Merge keys (`<<`) are no longer expanded, so a policy file that relies on one is rejected whole and the last good ruleset stays in force instead of a partially assembled rule taking effect. Unquoted dates load as strings rather than `Date` objects, and a mapping with a complex key is rejected instead of having that key flattened into a lossy string.
- The dashboard runtime-context panel now degrades to "none" when the agent harness config file cannot be parsed, rather than failing the whole dashboard state build on a file Agentwall does not own.

### Fixed
- OpenTimestamps proof files are named after the checkpoint digest instead of a counter that
  only advances on rotation. Two anchor passes without a rotation between them previously wrote
  the same filename, so each pass destroyed the proof the previous one had obtained. Anchoring
  on a schedule would have erased evidence at every interval.
- `agentwall verify` no longer reports "nothing anchored off-box yet" when the anchor log has
  entries. It reached that message whenever the anchor log and the checkpoint key were not both
  present, and said it in a state where it was false.

### Removed
- The direct `pino` dependency, which nothing imported. Fastify owns the logger instance the
  server actually uses and depends on pino itself, so the declared dependency only pinned a
  second, unused copy of pino 8 in the tree. Runtime dependencies are now three, `fastify`,
  `js-yaml`, and `zod`, and a clean install carries 11 fewer transitive packages.

## [0.1.0] - 2026-03-23

### Added
- Core policy evaluation API with provenance-aware decisions.
- Egress guardrails: default-deny, SSRF/private-range controls, host/scheme/port constraints.
- DLP inspection for common secrets and PII classes.
- Human approval flow with persistent queue backend.
- Dashboard views for decision stream, policy drilldowns, and approvals.
- Agent-harness monitor-first integration helpers and preflight adapters.
- Documentation: architecture overview and threat model.
- Community baseline files (`SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, CoC).
- CI workflow for lint/build/test/audit on push + pull requests.
