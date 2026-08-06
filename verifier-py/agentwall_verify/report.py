"""Rendering a result, in JSON for a harness and in prose for an operator.

The attestation list is not decoration. The three counters report the backend
state each anchor record claims about itself, and a reader who saw only
``confirmed: 1`` could reasonably think a Bitcoin block had been checked. The
list says what the proof actually reaches, which for a pending attestation is a
calendar and for a Bitcoin one is a value and a height still to be compared
against a block source.
"""

from __future__ import annotations

import json
import sys

from .evidence import Result

VERIFIER_NAME = "agentwall-verify-py"
VERIFIER_VERSION = "0.2.0"
CANON = "cu1"


def to_json(result: Result) -> str:
    payload = {
        "ok": result.ok,
        "layers": [
            {
                "name": layer.name,
                "ok": layer.ok,
                "detail": layer.detail,
                "problems": [str(problem) for problem in layer.problems],
            }
            for layer in result.layers
        ],
        "pending": result.pending,
        "confirmed": result.confirmed,
        "failed": result.failed,
        "attestations": result.attestations,
        "verifier": {
            "name": VERIFIER_NAME,
            "version": VERIFIER_VERSION,
            "language": "python",
            "canon": CANON,
        },
    }
    return json.dumps(payload, indent=2)


def _attestation_line(entry: dict) -> str:
    if entry["kind"] == "pending":
        return (
            "      anchor "
            + str(entry["anchor"])
            + ": pending at "
            + str(entry.get("calendar"))
            + ", which records that a calendar accepted a submission and nothing more"
        )
    if entry["kind"] == "bitcoin":
        return (
            "      anchor "
            + str(entry["anchor"])
            + ": leads to "
            + entry["value"]
            + ", claimed Merkle root of block "
            + str(entry["height"])
            + "; compare it with a Bitcoin source to finish the check"
        )
    return "      anchor " + str(entry["anchor"]) + ": attestation " + str(entry.get("tag")) + ", not recognized here"


def to_text(result: Result) -> str:
    lines = []
    for layer in result.layers:
        mark = "PASS" if layer.ok else "FAIL"
        lines.append(mark + "  " + layer.name.ljust(9) + layer.detail)
        for problem in layer.problems:
            lines.append("      " + str(problem))
        if layer.name == "anchored" and result.attestations:
            lines.append("      what the proofs reach:")
            for entry in result.attestations:
                lines.append(_attestation_line(entry))
    lines.append("")
    if result.ok:
        lines.append("All three layers verified. This says the evidence is internally consistent.")
        lines.append("It does not say the log is complete, and no anchor above bounds when this")
        lines.append("history existed until a Bitcoin attestation is compared with a block source.")
    else:
        lines.append("At least one layer did not verify. Each layer answers a different question,")
        lines.append("so read the failing one rather than the summary.")
    return "\n".join(lines) + "\n"


def emit(result: Result, as_json: bool, stream=sys.stdout) -> None:
    stream.write(to_json(result) + "\n" if as_json else to_text(result))
