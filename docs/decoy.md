# Decoy tokens

A decoy token is a synthetic credential that is planted somewhere an agent's chain can reach and
then never used by anything legitimate. There is no benign execution in which its exact bytes leave
the machine. So if those bytes ever appear in traffic AgentWall inspects, something read the place
you planted it and shipped what it found.

## Why this signal is different in kind

Everything else AgentWall reports is a judgement about traffic. The DLP scan says a string *looks
like* a credential. The injection scan says a passage *reads like* an instruction. Both are
classifiers: they have a false-positive rate, they have a false-negative rate, and both rates move
when the next agent framework formats its payloads differently.

A decoy is not a classifier and has no rate. Matching is against the exact registered value, byte
for byte, so the only way to produce a hit is to transmit the value. That turns the alert from *the
probability that something exfiltrated data* into *the observation that something did*. It is worth
being blunt about the trade: this is the highest-confidence detection here and also the narrowest
one. It tells you about the string you planted and about nothing else.

The exactness is load-bearing and is not a tuning knob. If matching ever became `AKIA[0-9A-Z]{16}`
the mechanism would inherit the error rate of every other detector, would fire on your real keys,
and would stop being proof of anything. There is no fuzzy mode and there will not be one.

## Generating one

```bash
agentwall decoy generate --kind aws-access-key --label billing-decoy --out ~/.agentwall/decoys.json
```

`--kind` picks the credential the token impersonates: `aws-access-key`, `github-pat`, `openai-key`,
`generic-secret`, or `url`. `--label` is an operator note kept with the token; it appears in the
audit record and in the generated variable name, so it is worth setting when you plant more than
one. `--out` appends the token to a decoy file, created at mode `0600`.

Without `--out`, the value exists only in that terminal. AgentWall cannot match a decoy it was
never told about, so a generated-and-discarded token is nothing.

The command prints the token and a ready-to-paste export block:

```
id         dcoy_4f2a91c07b3e
kind       aws-access-key
label      billing-decoy
createdAt  2026-08-05T09:14:22.481Z
value      AKIA3TQV7ZKM2XPD6R4L

# AgentWall decoy tokens. Not real credentials: they authenticate nowhere.
# If any of these values ever appears in outbound traffic, something read this environment
# and shipped it. AgentWall records that as a critical deny.

# dcoy_4f2a91c07b3e - billing-decoy (aws-access-key, minted 2026-08-05T09:14:22.481Z)
export AWS_ACCESS_KEY_ID_BILLING_DECOY='AKIA3TQV7ZKM2XPD6R4L'
```

To see what you have planted without printing any values:

```bash
agentwall decoy list --file ~/.agentwall/decoys.json
```

`list` shows id, kind, label, and creation time and never prints a value, so its output is safe to
paste into a ticket.

### Why the value looks real

A generated value is structurally valid for its kind: an `aws-access-key` decoy starts `AKIA`, is
twenty characters, and uses the base32 alphabet AWS uses; a `github-pat` decoy carries the correct
trailing CRC-32 that GitHub's own validators check. This matters because the thief filters.
Harvesters and prompt-injected agents run shape checks on what they scrape, and a token that fails
those checks is dropped by exactly the code the decoy exists to catch.

It is safe anyway because the randomness, not the malformedness, is what makes it useless. Every
value is drawn uniformly with `crypto.randomBytes` from the same namespace a real credential
occupies, so the chance of naming an issued key is the chance of guessing one: roughly 2^80 for
AWS, 2^178 for GitHub, 2^285 for OpenAI. Nothing is registered with any provider and nothing can
authenticate. That is a counting argument, not a vendor's promise, and it is the honest form of the
claim.

The `url` kind is the exception. It points at a `.decoy.invalid` hostname, which by RFC 2606 can
never resolve. The usual design points a decoy URL at a host that logs the hit, but AgentWall runs
no such host, and inventing a real-looking hostname would mean sending your exfiltration signal to
a domain somebody else may own. Detection here comes from AgentWall seeing the string, not from a
callback, so the URL does not need to resolve. The cost is that a human who reads the URL can tell
it is a decoy; this kind is for catching automated scrapers.

## Planting one

Three placements, in rough order of how much they cover:

**Environment variable.** Source the export block into the shell that launches your agent, or add
the lines to whatever writes its environment. This is the placement that catches "dump the env and
post it somewhere", which is the most common shape of agent credential theft, and it is why the
generated variable names impersonate real ones (`AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`) rather than
announcing themselves as decoys.

```bash
source <(agentwall decoy generate --kind aws-access-key --out ~/.agentwall/decoys.json | sed -n '/^export /p')
```

**Config file.** Put the value in a config the agent can read but has no reason to send anywhere -
a `.env` in the project root, a service block in an application config. This catches a tool that
reads project files wholesale and returns their contents into the model's context, from where they
travel.

**Fake credentials file.** Write a plausible `~/.aws/credentials` or a service-account JSON
containing only decoy values. This is the placement to use when there are no real credentials at
that path, because it is unambiguous: nothing legitimate has any reason to read a file that only
ever contained decoys.

```ini
[default]
aws_access_key_id = AKIA3TQV7ZKM2XPD6R4L
aws_secret_access_key = 0f1a...
```

Do not plant a decoy into a path that also holds a real credential unless you have checked that
the surrounding tooling tolerates the extra entry. A decoy that breaks a working deployment gets
removed, and a removed decoy detects nothing.

## What happens when one fires

Detection is a call to `scanForDecoys` on text a surface is about to forward. That call produces
one audit record per decoy matched, on the `identity` plane:

- `action` is `decoy:triggered`
- `decision` is `deny`, `riskLevel` is `critical`
- `matchedRules` is `["identity:deny-decoy-triggered"]`
- `detections` carries `det.identity.decoy.triggered`, mapped to ATT&CK T1552 (Unsecured
  Credentials) under Credential Access
- `metadata` carries `decoyId`, `decoyKind`, `decoyTriggered`, and `decoyLabel` when set

The record joins the same hash chain as every other decision, so `agentwall verify` covers it and
`agentwall anchor` can put it under a timestamp.

**The value is not in the record, and this is deliberate.** An audit log is read by more people
than the environment it protects: it gets tailed in a terminal, shipped to a SIEM, and pasted into
incident tickets. Writing the decoy into it would hand anyone with log access the exact string the
theft was after, and tell them precisely which string to strip from future traffic in order to run
the same theft unobserved. The id and label are enough to identify which decoy fired; the value
lives in your decoy file and nowhere else.

## The decoy file

The file holds plaintext values, because you need them to plant and AgentWall needs them to match.
There is no digest-only version of this.

It is written at mode `0600`, and `loadDecoys` refuses to read a file that group or other can
read, naming the mode and the fix. Refusing rather than warning is intentional: an attacker who
reads this file gains access to nothing, but does gain the ability to recognise your traps and
route around them, which costs you the detection without producing any sign that it is gone.

Saving over an existing file re-applies `0600`, so a file somebody loosened does not stay loose.

## Limits

Read these before you rely on a decoy for anything.

**Silence is not evidence of safety.** A decoy fires only if something reads and transmits that
exact value. An agent that exfiltrates a different secret, reads a file you did not seed, or copies
your data without touching your decoy produces exactly the same quiet as an agent that did nothing
wrong. Nothing about a decoy's stillness generalises to the rest of the system.

**It detects exfiltration of the planted value and nothing else.** This is not a monitor for
credential theft in general, and a hit tells you only that the specific string moved. It does not
tell you what else moved with it, when the read happened, or whether the same actor has other
access. It is the start of an investigation, not the conclusion of one.

**A decoy is only seen on surfaces AgentWall inspects.** The token is inert on its own; it fires
where something calls `scanForDecoys` on the content it is about to forward. Anything that leaves
by a path with no gate on it - a direct socket that bypasses the proxy, any body relayed by the
forward proxy, whether https and unreadable or http and simply never scanned, a channel the
deployment never routed through AgentWall - carries the decoy out without a record. Be precise
about the proxy in particular: no code on the proxy path calls `scanForDecoys`, so a decoy
crossing it is not detected on either scheme, and TLS is not the reason on the http one.
Planting a decoy in an environment variable
does not put a watcher on that variable; it only makes the theft recognisable *if* the theft
crosses a place that is watching.

**A decoy only works while it is secret.** Anyone who can read your decoy file, or who can see a
decoy value in a log or a screenshot, can filter it out of their traffic. Treat the file as a
credential even though its contents are not credentials.

**Shape realism has a ceiling.** The values pass the regexes and, for GitHub, the checksum. They do
not pass an authentication attempt, so an attacker who validates loot against the live provider
before shipping it will discard the decoy and you will see nothing. This mechanism catches
collect-and-forward behaviour, which is the overwhelming majority of it, not a careful adversary
with a validation step.
