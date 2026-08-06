"""The anchor log: the ``anchored`` layer.

The rule that shapes this whole module is that an anchor is judged by the proof
bytes it points at, never by the status it reports about itself. A record can
say ``confirmed`` and carry a proof that reaches only a calendar, or say
``pending`` and carry an error meaning it never reached one. Believing either
field would turn the layer that exists to prevent overclaiming into the place
the overclaim is made.
"""

from __future__ import annotations

import os

from . import codes
from .canon import sha256_hex
from .checkpoint import Checkpoint, digest_material, read_checkpoint, rebuild_problem, verify_signature
from .codes import Problem
from .ots import ProofError, parse_proof
from .tokens import OBJECT, STRING, DuplicateKey, JsonError, Value, parse

CONFIRMED = "confirmed"
PENDING = "pending"
FAILED = "failed"


class Anchor:
    """One anchor submission, after the evidence has been consulted."""

    __slots__ = ("line_no", "digest", "state", "checkpoint", "attestations", "proof_path")

    def __init__(self, line_no: int) -> None:
        self.line_no = line_no
        self.digest = ""
        self.state = FAILED
        self.checkpoint: Checkpoint | None = None
        self.attestations: list = []
        self.proof_path: str | None = None


class AnchorLog:
    __slots__ = ("path", "present", "anchors", "problems")

    def __init__(self, path: str) -> None:
        self.path = path
        self.present = False
        self.anchors: list[Anchor] = []
        self.problems: list[Problem] = []

    def counts(self) -> tuple[int, int, int]:
        pending = confirmed = failed = 0
        for anchor in self.anchors:
            if anchor.state == CONFIRMED:
                confirmed += 1
            elif anchor.state == PENDING:
                pending += 1
            else:
                failed += 1
        return pending, confirmed, failed


def find_proof(recorded: str, anchors_dir: str, proofs_dir: str) -> str | None:
    """Locate a proof from the path the record carries.

    ``proofPath`` holds whatever the producer wrote, relative to the producer's
    working directory unless it is absolute, and the proof directory and the
    anchor log directory are configured independently. So the recorded path is
    tried as written, then relative to the anchor log, and finally the recorded
    base name is looked for in the proof directory this verifier was given.
    That last step is what lets a whole evidence directory be checked after it
    has been copied to another host.

    The base name is never derived from the digest. Naming a proof after its
    digest is a writer convention, and the recorded path is the only thing that
    finds a file named any other way.
    """
    if not recorded:
        return None
    candidates = [recorded]
    if not os.path.isabs(recorded):
        candidates.append(os.path.join(anchors_dir, recorded))
    candidates.append(os.path.join(proofs_dir, os.path.basename(recorded)))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def read_anchor_log(path: str, proofs_dir: str) -> AnchorLog:
    """Read the anchor log and settle each record against the evidence."""
    out = AnchorLog(path)
    try:
        raw = open(path, "rb").read()
    except FileNotFoundError:
        return out
    except OSError as err:
        out.present = True
        out.problems.append(Problem(codes.ANCHOR_PARSE_ERROR, os.path.basename(path) + ": " + str(err)))
        return out
    out.present = True
    anchors_dir = os.path.dirname(os.path.abspath(path))

    for i, chunk in enumerate(raw.split(b"\n")):
        if not chunk.strip():
            continue
        line_no = i + 1
        where = os.path.basename(path) + " line " + str(line_no)
        try:
            node = parse(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            out.problems.append(Problem(codes.ANCHOR_PARSE_ERROR, where + " is not UTF-8"))
            continue
        except DuplicateKey as err:
            out.problems.append(Problem(codes.DUP_KEY, where + " has two members named " + repr(err.key)))
            continue
        except JsonError as err:
            out.problems.append(Problem(codes.ANCHOR_PARSE_ERROR, where + ": " + err.message))
            continue
        out.anchors.append(_settle(out, where, line_no, node, anchors_dir, proofs_dir))

    return out


def _settle(out: AnchorLog, where: str, line_no: int, node: Value, anchors_dir: str, proofs_dir: str) -> Anchor:
    anchor = Anchor(line_no)
    if node.kind != OBJECT:
        out.problems.append(Problem(codes.ANCHOR_MALFORMED, where + " is not a JSON object"))
        return anchor

    digest_node = node.get("digest")
    if digest_node is None or digest_node.kind != STRING:
        out.problems.append(Problem(codes.ANCHOR_MALFORMED, where + " has no string digest"))
        return anchor
    anchor.digest = digest_node.text

    error_node = node.get("error")
    errored = error_node is not None and not error_node.is_null and not (error_node.kind == STRING and error_node.text == "")
    if errored:
        detail = error_node.text if error_node.kind == STRING else error_node.lexeme
        # The submission never reached a calendar, whatever the status says.
        out.problems.append(Problem(codes.ANCHOR_FAILED, where + " records a failed submission: " + detail))

    checkpoint_node = node.get("checkpoint")
    checkpoint = None if checkpoint_node is None else read_checkpoint(checkpoint_node)
    if checkpoint is None:
        out.problems.append(Problem(codes.CHECKPOINT_MALFORMED, where + " carries no usable checkpoint"))
        return anchor
    anchor.checkpoint = checkpoint

    material = digest_material(checkpoint_node)
    if material is None or sha256_hex(material) != anchor.digest:
        out.problems.append(
            Problem(
                codes.DIGEST_MISMATCH,
                where + " submitted " + anchor.digest[:12] + " which is not the digest of the checkpoint it carries",
            )
        )

    ok, reason = verify_signature(checkpoint)
    if not ok:
        out.problems.append(Problem(codes.CHECKPOINT_BAD_SIGNATURE, where + " checkpoint " + reason))

    _bucket(out, where, node, anchor, errored)

    recorded_node = node.get("proofPath")
    recorded = recorded_node.text if recorded_node is not None and recorded_node.kind == STRING else ""
    anchor.proof_path = find_proof(recorded, anchors_dir, proofs_dir)
    if anchor.proof_path is None:
        out.problems.append(
            Problem(codes.PROOF_MISSING, where + " points at proof " + repr(recorded) + " which is not on disk")
        )
        return anchor

    try:
        raw_digest = bytes.fromhex(anchor.digest)
    except ValueError:
        out.problems.append(Problem(codes.ANCHOR_MALFORMED, where + " has a digest that is not hex"))
        return anchor

    try:
        anchor.attestations = parse_proof(open(anchor.proof_path, "rb").read(), raw_digest)
    except OSError as err:
        out.problems.append(Problem(codes.PROOF_MISSING, where + " proof cannot be read: " + str(err)))
        return anchor
    except ProofError as err:
        out.problems.append(
            Problem(codes.PROOF_PARSE_ERROR, where + " proof " + os.path.basename(anchor.proof_path) + ": " + str(err))
        )
        return anchor

    if not anchor.attestations:
        out.problems.append(
            Problem(codes.PROOF_NO_ATTESTATION, where + " proof runs to the end without reaching an attestation")
        )
    return anchor


def _bucket(out: AnchorLog, where: str, node: Value, anchor: Anchor, errored: bool) -> None:
    """Place the record in exactly one of the three counters.

    The base is ``status`` and the sole override is ``error``. That is the
    precedence the format states, and the three counter names map onto the two
    status values plus the error case with nothing left over.

    An earlier reading of this module derived the buckets from the reached
    attestation instead. It is wrong, and the way it is wrong is worth keeping
    written down: a Bitcoin attestation is explicitly never a completed check,
    so an attestation-derived ``confirmed`` can only come from treating one as
    if it were. Deriving the counters from the proof makes ``confirmed``
    unreachable for an offline verifier on every possible input, while the
    format requires all three counts to be reported.

    None of which makes ``status`` trustworthy. It is the backend's claim, and
    the layer verdict beside it is what says whether the evidence supports the
    claim. The reached attestations are reported alongside so that a reader of
    ``confirmed`` can see what the proof actually reaches.
    """
    if errored:
        anchor.state = FAILED
        return
    status = node.get("status")
    if status is not None and status.kind == STRING:
        if status.text == CONFIRMED:
            anchor.state = CONFIRMED
            return
        if status.text == PENDING:
            anchor.state = PENDING
            return
    # The format enumerates exactly two statuses and demands exactly one of
    # three counts, so a record naming neither has no bucket to go in.
    shown = repr(status.text) if status is not None and status.kind == STRING else "no status"
    out.problems.append(Problem(codes.ANCHOR_MALFORMED, where + " reports " + shown + ", not pending or confirmed"))
    anchor.state = FAILED


def check_commitments(log: AnchorLog, rebuild_for) -> list[Problem]:
    """Require every checkpoint's composite to be rebuildable from the files."""
    problems: list[Problem] = []
    for anchor in log.anchors:
        if anchor.checkpoint is None:
            continue
        problem = rebuild_problem(anchor.checkpoint, rebuild_for(anchor.checkpoint.chain_index))
        if problem is not None:
            problems.append(problem)
    return problems


def check_pin(log: AnchorLog, pin: str) -> list[Problem]:
    """Pinning is what turns a self-consistent signature into evidence of who signed."""
    problems: list[Problem] = []
    for anchor in log.anchors:
        checkpoint = anchor.checkpoint
        if checkpoint is None:
            continue
        if checkpoint.public_key != pin:
            problems.append(
                Problem(
                    codes.CHECKPOINT_KEY_MISMATCH,
                    "anchor log line "
                    + str(anchor.line_no)
                    + " checkpoint is signed by a key that is not the pinned one",
                )
            )
    return problems


def describe(log: AnchorLog) -> list[dict]:
    """Every attestation the proofs reach, as the format requires them reported.

    A pending attestation is named with its calendar and nothing more. A
    Bitcoin attestation is named with the value it covers and the height that
    value is claimed to be the Merkle root of, which is one lookup away from
    being an answer and is not an answer yet. This list is what keeps a
    ``confirmed`` counter honest: it says what the proof actually reaches.
    """
    out: list[dict] = []
    for anchor in log.anchors:
        for attestation in anchor.attestations:
            entry = {
                "anchor": anchor.line_no,
                "kind": attestation.kind,
                "value": attestation.message.hex(),
            }
            if attestation.kind == "pending":
                entry["calendar"] = attestation.uri
            elif attestation.kind == "bitcoin":
                entry["height"] = attestation.height
                entry["note"] = "claimed Merkle root of this block; compare it with a Bitcoin source"
            else:
                entry["tag"] = attestation.tag.hex()
            out.append(entry)
    return out
