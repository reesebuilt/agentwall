"""Checkpoints: signed bytes, submitted digest, and the rebuilt composite.

Every constant is from the worked examples in docs/audit-format.md, including
a real Ed25519 signature over a real key, so these fail if this implementation
drifts from the document.
"""

from __future__ import annotations

import json

from agentwall_verify.canon import sha256_hex
from agentwall_verify.checkpoint import (
    composite,
    digest_material,
    live_tail_candidates,
    read_checkpoint,
    rebuild_problem,
    signed_bytes,
    verify_signature,
)
from agentwall_verify.chain import read_record_file
from agentwall_verify.manifest import Manifest
from agentwall_verify.tokens import parse
from helpers import digest_of, record, write_lines

CHECKPOINT = (
    '{"chainIndex":1,"hash":"fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0",'
    '"signedAt":"2026-01-01T00:00:03.000Z",'
    '"signature":"0Kt6u/CfbfxIdPm6Kgp6WpAzi8301ca8Zw7RpqOxoIq1BC4n6sOiY0eVOZTMfcOfo+eoTHH+CodhmYhYmh/ADg==",'
    '"publicKey":"MCowBQYDK2VwAyEAvU3AKdlPbYXhbkS1iwGM9tCjRnWfTL7kEErFXtyronE=",'
    '"algorithm":"ed25519"}'
)
COMPOSITE_HASH = "fa5a5cb74d756b22b61627f2dcf0e1b5435879010333ee7ea3dce3b29c0ab4e0"
SUBMITTED_DIGEST = "d39f84ad3463447e33fc23d9df11fe8052912c48e0d1c2f3eeb09bc3751edc94"
MANIFEST_HEAD = "8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428"
LIVE_TAIL_HASH = "bd5cb6e6d98cc93e166c79b0945889642a3c2e7fdad1892bab83044b76c51348"


def test_spec_composite_bytes_and_hash():
    material = composite(MANIFEST_HEAD, 1, (LIVE_TAIL_HASH, 1))
    assert material == (
        '{"manifestHead":"' + MANIFEST_HEAD + '","segments":1,'
        '"liveTail":{"finalHash":"' + LIVE_TAIL_HASH + '","count":1}}'
    )
    assert sha256_hex(material) == COMPOSITE_HASH


def test_empty_manifest_gives_a_bare_null_head():
    assert composite(None, 0, None) == '{"manifestHead":null,"segments":0,"liveTail":null}'


def test_spec_signed_bytes():
    assert signed_bytes(parse(CHECKPOINT)) == (
        '{"chainIndex":1,"hash":"' + COMPOSITE_HASH + '",'
        '"signedAt":"2026-01-01T00:00:03.000Z","algorithm":"ed25519"}'
    )


def test_spec_submitted_digest_differs_from_the_signed_bytes():
    material = digest_material(parse(CHECKPOINT))
    assert '"algorithm"' not in material
    assert '"signature"' in material and '"publicKey"' in material
    assert sha256_hex(material) == SUBMITTED_DIGEST


def test_spec_signature_verifies():
    ok, reason = verify_signature(read_checkpoint(parse(CHECKPOINT)))
    assert ok, reason


def test_one_flipped_bit_of_the_signature_fails():
    body = json.loads(CHECKPOINT)
    import base64

    raw = bytearray(base64.b64decode(body["signature"]))
    raw[0] ^= 1
    body["signature"] = base64.b64encode(bytes(raw)).decode()
    ok, _ = verify_signature(read_checkpoint(parse(json.dumps(body, separators=(",", ":")))))
    assert not ok


def test_one_changed_byte_of_the_signed_bytes_fails():
    body = json.loads(CHECKPOINT)
    body["signedAt"] = "2026-01-01T00:00:04.000Z"
    ok, _ = verify_signature(read_checkpoint(parse(json.dumps(body, separators=(",", ":")))))
    assert not ok


def _manifest():
    return Manifest("segments.jsonl")


def _checkpoint(chain_index, composite_hash):
    body = json.loads(CHECKPOINT)
    body["chainIndex"] = chain_index
    body["hash"] = composite_hash
    return read_checkpoint(parse(json.dumps(body, separators=(",", ":"))))


def test_a_growing_live_file_still_reproduces_its_committed_prefix(tmp_path):
    # A checkpoint commits a PREFIX and not a length, so records appended after
    # signing leave the committed pair reproducible. Every checkpoint but the
    # newest would fail otherwise.
    lines = [record({"n": 0}, 0, None)]
    for i in range(1, 5):
        lines.append(record({"n": i}, i, digest_of(lines[-1])))
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, lines[:2])
    live = read_record_file(path)
    committed = sha256_hex(composite(None, 0, (digest_of(lines[1]), 2)))

    write_lines(path, lines)
    grown = read_record_file(path)
    rebuild = live_tail_candidates(0, _manifest(), grown, [], {})
    assert rebuild_problem(_checkpoint(0, committed), rebuild) is None
    assert len(live.records) == 2


def test_a_rewritten_prefix_reproduces_from_nothing(tmp_path):
    lines = [record({"n": 0}, 0, None), None]
    lines[1] = record({"n": 1}, 1, digest_of(lines[0]))
    committed = sha256_hex(composite(None, 0, (digest_of(lines[1]), 2)))

    rewritten = [record({"n": 99}, 0, None)]
    rewritten.append(record({"n": 1}, 1, digest_of(rewritten[0])))
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, rewritten)
    rebuild = live_tail_candidates(0, _manifest(), read_record_file(path), [], {})
    problem = rebuild_problem(_checkpoint(0, committed), rebuild)
    assert problem is not None and problem.code == "live-tail-mismatch"


def test_a_manifest_shorter_than_the_checkpoint_is_reported(tmp_path):
    # Dropping the newest entries breaks no previousSegmentHash link, because
    # what remains still chains. The checkpoint is the only thing that notices.
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [record({"n": 0}, 0, None)])
    rebuild = live_tail_candidates(3, _manifest(), read_record_file(path), [], {})
    problem = rebuild_problem(_checkpoint(3, COMPOSITE_HASH), rebuild)
    assert problem is not None and problem.code == "manifest-too-short"


def test_the_null_tail_is_always_a_candidate(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [])
    committed = sha256_hex(composite(None, 0, None))
    rebuild = live_tail_candidates(0, _manifest(), read_record_file(path), [], {})
    assert rebuild_problem(_checkpoint(0, committed), rebuild) is None
