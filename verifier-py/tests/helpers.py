"""Fixtures shared by the tests.

The two record lines here are copied verbatim from the worked examples in
docs/audit-format.md, including their hashes, so a test that uses them is
anchored to the document rather than to this implementation.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentwall_verify.canon import canon, hash_material, sha256_hex  # noqa: E402
from agentwall_verify.tokens import parse  # noqa: E402

RECORD_0 = (
    '{"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","timestamp":"2026-01-01T00:00:00.000Z","agentId":"curl",'
    '"plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],'
    '"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,'
    '"metadata":{"host":"example.com","port":"443","durationMs":"378"},'
    '"integrity":{"chainIndex":0,'
    '"hash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303",'
    '"previousHash":null,"algorithm":"sha256","status":"chained-local","canon":"cu1"}}'
)
HASH_0 = "d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303"

RECORD_1 = (
    '{"id":"01JQ8Z0N2C4M8P1S6D3F9G7H2K","timestamp":"2026-01-01T00:00:01.000Z","agentId":"curl",'
    '"plane":"network","action":"egress:https","decision":"allow","riskLevel":"low","matchedRules":[],'
    '"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,"highRiskFlow":false,'
    '"metadata":{"host":"example.com","port":"443","durationMs":"412"},'
    '"integrity":{"chainIndex":1,'
    '"hash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428",'
    '"previousHash":"d0164214314bbdebbb8dcb8aaf8936f4da253c1ba7f06c22d25a1885d7344303",'
    '"algorithm":"sha256","status":"chained-local","canon":"cu1"}}'
)
HASH_1 = "8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428"


def record(payload: dict, index: int, previous: str | None) -> str:
    """Build a well formed record line around an arbitrary payload.

    The hash derivation this uses is pinned independently by the spec vectors
    in test_canon, so using it to build fixtures is not circular: those tests
    would fail first if the derivation drifted.
    """
    previous_lexeme = "null" if previous is None else '"' + previous + '"'
    body = canon(parse(json.dumps(payload, separators=(",", ":"))))
    digest = sha256_hex(hash_material(str(index), previous_lexeme, body))
    full = dict(payload)
    full["integrity"] = {
        "chainIndex": index,
        "hash": digest,
        "previousHash": previous,
        "algorithm": "sha256",
        "status": "chained-local",
        "canon": "cu1",
    }
    return json.dumps(full, separators=(",", ":"))


def digest_of(line: str) -> str:
    parsed = parse(line)
    integrity = parsed.get("integrity")
    return integrity.get("hash").text


def write_lines(path: str, lines: list, trailing_newline: bool = True) -> None:
    body = "\n".join(lines)
    if trailing_newline:
        body += "\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
