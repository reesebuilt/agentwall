# Quick Tutorial 06: Bring Up Your First Real Telegram Topic

Time: 90 seconds
Audience: operator standing up the first live Agentwall lane on a real Telegram chat

## Goal

Take exactly one Telegram topic from "unmanaged" to "Agentwall is in front of it":
identify the chat and thread, set the channel profile to `Answer only`, run the
proof suite, capture the audit IDs, and know how to lock it down if the lane
turns hostile.

## Prerequisites

- Local Agentwall dashboard reachable at `http://127.0.0.1:3015`.
- `policy.configPath` configured (channel firewall profile mutations require it).
- The Telegram chat id and `message_thread_id` for the topic you intend to put
  under containment. Get them from the gateway logs of whatever bot is already
  posting there. Treat both as sensitive and do not paste them outside the
  operator console.
- An `agentId` you control in Agentwall. If you do not yet have a dedicated id,
  start with `agent-1` and rename later when you split lanes.

## Walkthrough

1. Identify the topic. From the live gateway logs, capture:
   - `chat_id` (negative for supergroups; the id below is Telegram's
     documentation placeholder, substitute your own)
   - `message_thread_id` (e.g. `4242`)
   - canonical `channelId` form: `telegram:<chat_id>:<thread_id>`
2. Run the bringup helper from the repo root:
   ```bash
   node scripts/telegram-channel-bringup.js \
     --agent-id agent-1 \
     --chat-id -1001234567890 \
     --thread-id 4242
   ```
   The helper:
   - sets the channel-firewall profile to `answer_only` for that lane, and
   - runs `/api/dashboard/proof/communication-channel` to verify containment.
3. Read the printed summary. You want:
   - `proof: passed (5/5)` (or at minimum, every required check `PASS`)
   - one `auditEventId` per check — these are your evidence handles
4. Open the dashboard channel panel and confirm the lane row now shows
   `Answer only`. The matched rules should include
   `channel:deny-filesystem-mutation`, `channel:deny-sensitive-data-access`,
   `channel:redact-pii-content-egress`, and `channel:deny-sensitive-content-egress`.

## Proof

Success means the helper exits with code `0` and the printed checks include:

- `safe_reply` decision `allow`
- `write_file_denied` decision `deny`
- `secret_access_denied` decision `deny`
- `pii_reply_redacted` decision `redact`
- `secret_reply_denied` decision `deny`

Each line carries an `auditEventId` you can use to drill into the audit feed
from the dashboard.

## If the lane turns hostile

If you see unexpected attempts on this topic — for example sustained tool calls
from an account you did not authorize — switch the profile to locked down and
stop accepting traffic until you understand it:

```bash
node scripts/telegram-channel-bringup.js \
  --agent-id agent-1 \
  --chat-id -1001234567890 \
  --thread-id 4242 \
  --profile locked_down || true
```

`locked_down` keeps observation but denies everything else for that
`(agentId, channelId)` lane. The helper's proof suite is tuned for the
`answer_only` bringup path, so a locked-down run may report `attention` because
safe replies and PII redaction are also denied. That is acceptable during
containment. Investigate using the audit IDs from the last passing `answer_only`
proof run, then re-bring up the lane with `answer_only` only after the source is
explained.

## Safety note

Do not put real chat ids, thread ids, or bot tokens in screenshots or shared
docs. The helper never reads or prints secrets, and the dashboard payload is
verified clean by `scripts/verify-live.sh`. Keep that discipline.

## Related

- `docs/tutorials/01-telegram-answer-only.md` — dashboard-only walkthrough of
  the same containment loop, no helper script.
- `docs/tutorials/04-approval-queue.md` — what to do with the audit events the
  proof suite produces.
