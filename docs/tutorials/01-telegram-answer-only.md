# Quick Tutorial 01: Put a Telegram Topic in Answer Only

Time: 60-90 seconds
Audience: new Agentwall operator

## Goal

Configure one Telegram topic so an agent can answer normally but cannot mutate files, read secrets, or leak sensitive content back into chat.

## Walkthrough

1. Open Agentwall Dashboard.
2. Stay in Operator View.
3. In `Rules for Telegram Channels`, choose the target Telegram topic.
4. Apply profile: `Answer only`.
5. Run/prove the guardrail checks:
   - safe reply: allow
   - file write: deny
   - secret read: deny
   - PII-bearing reply: redact or block depending on policy
6. Confirm the channel row shows managed posture.

## Proof

Success means:
- safe answer returns `allow`
- `write_file` returns `deny`
- `read_secret` returns `deny`
- egress policy redacts or blocks sensitive chat replies
- audit feed records the decisions

## Safety note

Do not expose raw Telegram chat IDs or thread IDs in screenshots or shared output. Use a redacted lane label like `telegram:[redacted]:[topic]`.
