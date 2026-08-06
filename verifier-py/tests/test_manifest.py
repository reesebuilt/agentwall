"""The rotation manifest, and its binding to the bytes it names."""

from __future__ import annotations

import json
import os

from agentwall_verify import codes
from agentwall_verify.canon import sha256_hex
from agentwall_verify.chain import read_record_file
from agentwall_verify.manifest import bind_segments, entry_hash_material, read_manifest
from agentwall_verify.tokens import parse
from helpers import HASH_1, RECORD_0, RECORD_1, digest_of, record, write_lines

SPEC_ENTRY_BYTES = (
    '{"path":"audit.1.jsonl","count":2,"firstIndex":0,"lastIndex":1,'
    '"finalHash":"8b16daf09164d3e1334b0e405e54461e0ba2867d1edd60bf0ce19aed914a2428",'
    '"previousSegmentHash":null,"sealedAt":"2026-01-01T00:00:02.000Z"}'
)
SPEC_ENTRY_HASH = "6172869bd41e220a1ee64372e9aea4a68d8b11e9bb675a6f11611a2890d5f861"


def entry(path, count, first, last, final, previous, sealed_at="2026-01-01T00:00:02.000Z"):
    body = {
        "path": path,
        "count": count,
        "firstIndex": first,
        "lastIndex": last,
        "finalHash": final,
        "previousSegmentHash": previous,
        "sealedAt": sealed_at,
    }
    material = entry_hash_material(parse(json.dumps(body, separators=(",", ":"))))
    body["entryHash"] = sha256_hex(material)
    return json.dumps(body, separators=(",", ":"))


def fatal_codes(problems):
    return [problem.code for problem in problems if problem.fatal]


def test_spec_worked_entry_hash():
    assert entry_hash_material(parse(SPEC_ENTRY_BYTES)) == SPEC_ENTRY_BYTES
    assert sha256_hex(SPEC_ENTRY_BYTES) == SPEC_ENTRY_HASH


def test_entry_hash_member_order_is_fixed_by_the_format_not_by_the_line():
    # The same entry with its members written in another order hashes the same,
    # because the material is assembled by name.
    shuffled = json.dumps(dict(reversed(list(json.loads(SPEC_ENTRY_BYTES).items()))), separators=(",", ":"))
    assert shuffled != SPEC_ENTRY_BYTES
    assert entry_hash_material(parse(shuffled)) == SPEC_ENTRY_BYTES


def build(tmp_path, segment_lines, manifest_entries):
    for name, lines in segment_lines.items():
        write_lines(str(tmp_path / name), lines)
    write_lines(str(tmp_path / "segments.jsonl"), manifest_entries)
    manifest = read_manifest(str(tmp_path / "segments.jsonl"))
    segments = {}
    for name in segment_lines:
        full = str(tmp_path / name)
        segments[os.path.realpath(full)] = read_record_file(full)
    return manifest, segments


def test_a_matching_segment_binds(tmp_path):
    manifest, segments = build(
        tmp_path,
        {"audit.jsonl.1": [RECORD_0, RECORD_1]},
        [entry("audit.jsonl.1", 2, 0, 1, HASH_1, None)],
    )
    assert fatal_codes(manifest.problems) == []
    assert fatal_codes(bind_segments(manifest, segments)) == []


def test_edited_count_breaks_the_entry_hash(tmp_path):
    line = json.loads(entry("audit.jsonl.1", 2, 0, 1, HASH_1, None))
    line["count"] = 3
    manifest, _ = build(tmp_path, {"audit.jsonl.1": [RECORD_0, RECORD_1]}, [json.dumps(line, separators=(",", ":"))])
    assert codes.MANIFEST_ENTRY_HASH in fatal_codes(manifest.problems)


def test_removing_a_middle_entry_breaks_the_following_link(tmp_path):
    first = entry("audit.jsonl.1", 2, 0, 1, "a" * 64, None)
    third = entry("audit.jsonl.3", 2, 4, 5, "c" * 64, "b" * 64)
    write_lines(str(tmp_path / "segments.jsonl"), [first, third])
    manifest = read_manifest(str(tmp_path / "segments.jsonl"))
    assert codes.MANIFEST_LINK_BREAK in fatal_codes(manifest.problems)


def test_a_rewritten_segment_that_still_self_verifies_is_caught(tmp_path):
    # The segment's own chain was rebuilt, so `chained` passes and only the
    # manifest notices. This is the whole reason entries are bound to bytes.
    rebuilt = [record({"a": 1}, 0, None)]
    rebuilt.append(record({"a": 2}, 1, digest_of(rebuilt[0])))
    manifest, segments = build(
        tmp_path,
        {"audit.jsonl.1": rebuilt},
        [entry("audit.jsonl.1", 2, 0, 1, HASH_1, None)],
    )
    assert codes.SEGMENT_CONTENT_MISMATCH in fatal_codes(bind_segments(manifest, segments))


def test_an_absent_segment_is_a_different_finding_from_a_contradicting_one(tmp_path):
    manifest, segments = build(tmp_path, {}, [entry("audit.jsonl.1", 2, 0, 1, HASH_1, None)])
    reported = [problem.code for problem in bind_segments(manifest, segments)]
    assert reported == [codes.SEGMENT_MISSING]


def test_a_segment_truncated_to_nothing_is_not_a_pass(tmp_path):
    manifest, segments = build(tmp_path, {"audit.jsonl.1": []}, [entry("audit.jsonl.1", 2, 0, 1, HASH_1, None)])
    assert codes.SEGMENT_CONTENT_MISMATCH in fatal_codes(bind_segments(manifest, segments))


def test_relative_path_resolves_against_the_manifest_not_the_working_directory(tmp_path, monkeypatch):
    # The same evidence must verify from any directory, or the verdict becomes
    # a property of the operator's shell.
    manifest, segments = build(
        tmp_path,
        {"audit.jsonl.1": [RECORD_0, RECORD_1]},
        [entry("audit.jsonl.1", 2, 0, 1, HASH_1, None)],
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    reread = read_manifest(str(tmp_path / "segments.jsonl"))
    assert fatal_codes(bind_segments(reread, segments)) == []


def test_index_span_mismatch_is_named_directly(tmp_path):
    manifest, segments = build(
        tmp_path,
        {"audit.jsonl.1": [RECORD_0, RECORD_1]},
        [entry("audit.jsonl.1", 2, 4, 5, HASH_1, None)],
    )
    reported = bind_segments(manifest, segments)
    assert codes.SEGMENT_CONTENT_MISMATCH in [problem.code for problem in reported]
    assert any("spans indexes 0..1" in problem.text for problem in reported)


def test_absent_manifest_is_not_an_error(tmp_path):
    manifest = read_manifest(str(tmp_path / "segments.jsonl"))
    assert not manifest.present
    assert manifest.problems == []
    assert manifest.entries == []
