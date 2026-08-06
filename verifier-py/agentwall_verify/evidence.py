"""Finding the evidence files and reaching the three verdicts.

The three layers answer different questions and fail independently, so nothing
here collapses them. ``chained`` passing tells an operator nothing about
whether anything was anchored, and ``anchored`` passing tells them nothing
about whether the log is complete.
"""

from __future__ import annotations

import os

from . import codes
from .anchor import AnchorLog, check_commitments, check_pin, describe, read_anchor_log
from .chain import RecordFile, read_record_file
from .checkpoint import live_tail_candidates
from .codes import Problem
from .manifest import Manifest, bind_segments, read_manifest

CHAINED = "chained"
LINKED = "linked"
ANCHORED = "anchored"


class Layer:
    __slots__ = ("name", "ok", "detail", "problems")

    def __init__(self, name: str, ok: bool, detail: str, problems: list[Problem]) -> None:
        self.name = name
        self.ok = ok
        self.detail = detail
        self.problems = problems


class Paths:
    __slots__ = ("audit", "manifest", "anchors", "proofs")

    def __init__(self, audit: str, manifest: str = "", anchors: str = "", proofs: str = "") -> None:
        directory = os.path.dirname(os.path.abspath(audit))
        self.audit = audit
        self.manifest = manifest or os.path.join(directory, "segments.jsonl")
        self.anchors = anchors or os.path.join(directory, "anchors.jsonl")
        self.proofs = proofs or os.path.join(directory, "proofs")


class Result:
    __slots__ = ("layers", "pending", "confirmed", "failed", "attestations")

    def __init__(
        self,
        layers: list[Layer],
        pending: int,
        confirmed: int,
        failed: int,
        attestations: list[dict],
    ) -> None:
        self.layers = layers
        self.pending = pending
        self.confirmed = confirmed
        self.failed = failed
        self.attestations = attestations

    @property
    def ok(self) -> bool:
        return all(layer.ok for layer in self.layers)


def _rotation_sort_key(name: str) -> tuple:
    """Order audit.jsonl.2 before audit.jsonl.10 without assuming either exists."""
    suffix = name.rsplit(".", 1)[-1]
    if suffix.isdigit():
        return (0, int(suffix), name)
    return (1, 0, name)


def discover_rotations(paths: Paths) -> list[str]:
    """Rotated segments beside the audit file.

    The defaults are ``<audit>.1``, ``<audit>.2``, or a date-suffixed variant,
    so anything sharing the audit file's name plus a suffix is a candidate. The
    manifest, the anchor log and the proof directory are named independently
    and are excluded outright rather than left to a naming coincidence.
    """
    directory = os.path.dirname(os.path.abspath(paths.audit))
    base = os.path.basename(paths.audit)
    excluded = {
        os.path.realpath(paths.audit),
        os.path.realpath(paths.manifest),
        os.path.realpath(paths.anchors),
        os.path.realpath(paths.proofs),
    }
    found = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for name in names:
        if not name.startswith(base + "."):
            continue
        full = os.path.join(directory, name)
        if os.path.realpath(full) in excluded or not os.path.isfile(full):
            continue
        found.append(full)
    return sorted(found, key=lambda p: _rotation_sort_key(os.path.basename(p)))


def verify(paths: Paths, pin: str = "") -> Result:
    """Read every evidence file once and report the three layers separately."""
    live = read_record_file(paths.audit)
    manifest = read_manifest(paths.manifest)

    record_files: dict[str, RecordFile] = {os.path.realpath(paths.audit): live}
    rotations: list[RecordFile] = []
    for path in discover_rotations(paths):
        segment = read_record_file(path)
        record_files[os.path.realpath(path)] = segment
        rotations.append(segment)

    sealed_paths = set()
    for entry in manifest.entries:
        key = os.path.realpath(entry.resolved)
        sealed_paths.add(key)
        if key not in record_files:
            # Named by the manifest but somewhere the rotation naming does not
            # reach. It still has to be read, because the manifest vouches for
            # its contents and the linked layer checks that claim.
            record_files[key] = read_record_file(entry.resolved)

    unsealed = [segment for segment in rotations if os.path.realpath(segment.path) not in sealed_paths]

    chained_problems: list[Problem] = list(live.problems)
    for key in sorted(record_files):
        if key == os.path.realpath(paths.audit):
            continue
        chained_problems.extend(record_files[key].problems)

    linked_problems: list[Problem] = list(manifest.problems)
    if manifest.present:
        linked_problems.extend(bind_segments(manifest, record_files))
    for segment in unsealed:
        # Between a rotation and the next seal this is the normal state, so it
        # is reported and does not sink the layer. The format says such a file
        # sits outside the anchor; it does not say the manifest is wrong.
        linked_problems.append(
            Problem(
                codes.SEGMENT_UNSEALED,
                os.path.basename(segment.path) + " is on disk, absent from the manifest, and outside the anchor",
                fatal=False,
            )
        )

    log = read_anchor_log(paths.anchors, paths.proofs)
    anchored_problems: list[Problem] = list(log.problems)
    if log.present:
        anchored_problems.extend(
            check_commitments(
                log,
                lambda index: live_tail_candidates(index, manifest, live, unsealed, record_files),
            )
        )
        if pin:
            anchored_problems.extend(check_pin(log, pin))

    pending, confirmed, failed = log.counts()

    layers = [
        Layer(CHAINED, _clean(chained_problems), _chained_detail(live, record_files), chained_problems),
        Layer(LINKED, _clean(linked_problems), _linked_detail(manifest), linked_problems),
        Layer(
            ANCHORED,
            log.present and bool(log.anchors) and _clean(anchored_problems),
            _anchored_detail(log, pending, confirmed, failed),
            _anchored_problems(log, anchored_problems),
        ),
    ]
    return Result(layers, pending, confirmed, failed, describe(log))


def _clean(problems: list[Problem]) -> bool:
    return not any(problem.fatal for problem in problems)


def _anchored_problems(log: AnchorLog, problems: list[Problem]) -> list[Problem]:
    if not log.present:
        return [Problem(codes.ANCHOR_LOG_MISSING, "no anchor log, so nothing bounds when this history existed")] + problems
    if not log.anchors:
        return [Problem(codes.NO_ANCHORS, "the anchor log holds no submission")] + problems
    return problems


def _chained_detail(live: RecordFile, record_files: dict[str, RecordFile]) -> str:
    records = sum(len(f.records) for f in record_files.values())
    return str(records) + " record(s) across " + str(len(record_files)) + " file(s)"


def _linked_detail(manifest: Manifest) -> str:
    if not manifest.present:
        return "no rotation manifest, so no sealed segment is vouched for"
    return str(len(manifest.entries)) + " sealed segment(s)"


def _anchored_detail(log: AnchorLog, pending: int, confirmed: int, failed: int) -> str:
    if not log.present:
        return "no anchor log"
    # The counters report the backend state each record claims. Whether the
    # evidence supports the claim is the layer verdict beside them, and what
    # the proofs actually reach is the attestation list below them.
    return (
        str(len(log.anchors))
        + " anchor(s), by the state each record reports: "
        + str(confirmed)
        + " confirmed, "
        + str(pending)
        + " pending, "
        + str(failed)
        + " failed"
    )
