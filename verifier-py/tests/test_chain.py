"""The chain rules, including the ones that must NOT fire."""

from __future__ import annotations

from agentwall_verify import codes
from agentwall_verify.chain import read_record_file
from helpers import HASH_0, RECORD_0, RECORD_1, digest_of, record, write_lines


def fatal_codes(result):
    return [problem.code for problem in result.problems if problem.fatal]


def all_codes(result):
    return [problem.code for problem in result.problems]


def test_two_spec_records_chain(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [RECORD_0, RECORD_1])
    result = read_record_file(path)
    assert fatal_codes(result) == []
    assert [r.index for r in result.records] == [0, 1]
    assert result.records[1].hash == digest_of(RECORD_1)


def test_blank_lines_are_not_records(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [RECORD_0, "", "   ", RECORD_1, ""])
    result = read_record_file(path)
    assert fatal_codes(result) == []
    assert len(result.records) == 2


def test_a_file_may_start_at_a_non_zero_index(tmp_path):
    # A chain that continues across a rotation starts its next file at the
    # index it had reached, so this is not a break.
    first = record({"a": 1}, 7, "b" * 64)
    second = record({"a": 2}, 8, digest_of(first))
    path = str(tmp_path / "audit.jsonl.1")
    write_lines(path, [first, second])
    assert fatal_codes(read_record_file(path)) == []


def test_non_zero_first_index_with_null_previous_is_a_break(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [record({"a": 1}, 7, None)])
    assert codes.LINK_BREAK in fatal_codes(read_record_file(path))


def test_index_gap_is_reported(tmp_path):
    first = record({"a": 1}, 0, None)
    second = record({"a": 2}, 2, digest_of(first))
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, second])
    assert codes.INDEX_GAP in fatal_codes(read_record_file(path))


def test_link_break_is_reported(tmp_path):
    first = record({"a": 1}, 0, None)
    second = record({"a": 2}, 1, "c" * 64)
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, second])
    assert codes.LINK_BREAK in fatal_codes(read_record_file(path))


def test_index_reuse_is_named_separately(tmp_path):
    # Two writers each keeping their own chain state interleave into one file.
    first = record({"a": 1}, 0, None)
    second = record({"a": 2}, 0, None)
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, second])
    reported = all_codes(read_record_file(path))
    assert codes.INDEX_REUSE in reported


def test_edited_payload_is_caught_at_the_edited_record(tmp_path):
    edited = RECORD_0.replace('"decision":"allow"', '"decision":"deny"')
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [edited])
    assert fatal_codes(read_record_file(path)) == [codes.HASH_MISMATCH]


def test_one_edit_does_not_cascade_into_link_breaks(tmp_path):
    # Linkage is judged against the hash the file records, so a single altered
    # record yields one finding rather than one per record after it.
    edited = RECORD_0.replace('"durationMs":"378"', '"durationMs":"999"')
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [edited, RECORD_1])
    reported = fatal_codes(read_record_file(path))
    assert reported == [codes.HASH_MISMATCH]


def test_unmarked_canon_mismatch_claims_neither_cause(tmp_path):
    line = RECORD_0.replace(',"canon":"cu1"', "").replace('"decision":"allow"', '"decision":"deny"')
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [line])
    assert codes.HASH_MISMATCH_OR_LEGACY in fatal_codes(read_record_file(path))


def test_unknown_canon_has_no_derivation(tmp_path):
    line = RECORD_0.replace('"canon":"cu1"', '"canon":"cu2"')
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [line])
    assert codes.UNKNOWN_CANON in fatal_codes(read_record_file(path))


def test_other_algorithm_has_no_derivation(tmp_path):
    line = RECORD_0.replace('"algorithm":"sha256"', '"algorithm":"sha512"')
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [line])
    assert codes.UNSUPPORTED_ALGORITHM in fatal_codes(read_record_file(path))


def test_missing_integrity_is_a_failure(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, ['{"a":1}'])
    assert codes.MISSING_INTEGRITY in fatal_codes(read_record_file(path))


def test_torn_final_line_is_not_treated_as_tampering(tmp_path):
    # A process killed mid-append produces exactly one of these, legitimately.
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [RECORD_0, RECORD_1, '{"id":"evt-3","agentI'], trailing_newline=False)
    result = read_record_file(path)
    assert result.torn_tail
    assert fatal_codes(result) == []
    assert codes.TORN_TAIL in all_codes(result)
    assert len(result.records) == 2


def test_torn_line_that_is_not_final_is_a_failure(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [RECORD_0, '{"id":"evt-3","agentI', RECORD_1])
    result = read_record_file(path)
    assert not result.torn_tail
    assert codes.PARSE_ERROR in fatal_codes(result)


def test_final_line_that_is_garbage_rather_than_cut_short_is_a_failure(tmp_path):
    # Truncation is what the format excuses. A final line with a mid-line
    # syntax error was not produced by a kill.
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [RECORD_0, '{"a":1}}}'])
    result = read_record_file(path)
    assert not result.torn_tail
    assert codes.PARSE_ERROR in fatal_codes(result)


def test_duplicate_key_record_counts_toward_nothing(tmp_path):
    # The record either side of it are judged against each other, which is why
    # removing a shadowed record shows up as a gap rather than as nothing.
    first = record({"a": 1}, 0, None)
    third = record({"a": 3}, 2, "d" * 64)
    shadowed = '{"a":2,"a":9,"integrity":{"chainIndex":1,"hash":"' + "e" * 64 + '","previousHash":"' + digest_of(first) + '","algorithm":"sha256","status":"chained-local","canon":"cu1"}}'
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, shadowed, third])
    result = read_record_file(path)
    reported = fatal_codes(result)
    assert codes.DUP_KEY in reported
    assert codes.INDEX_GAP in reported
    assert len(result.records) == 2


def test_gap_declaration_is_reported_and_non_fatal(tmp_path):
    first = record({"a": 1}, 0, None)
    declaration = record(
        {"action": "audit:chain-gap", "metadata": {"droppedRecords": "4"}},
        1,
        digest_of(first),
    )
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, declaration])
    result = read_record_file(path)
    assert fatal_codes(result) == []
    assert codes.CHAIN_GAP_DECLARED in all_codes(result)


def test_gap_declaration_excuses_nothing(tmp_path):
    # An index gap is judged the same whether or not a declaration is present,
    # because the record is the writer's account of a hole and not a licence to
    # have one.
    first = record({"a": 1}, 0, None)
    declaration = record(
        {"action": "audit:chain-gap", "metadata": {"droppedRecords": "4"}},
        1,
        digest_of(first),
    )
    jumped = record({"a": 3}, 9, digest_of(declaration))
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [first, declaration, jumped])
    result = read_record_file(path)
    assert codes.INDEX_GAP in fatal_codes(result)
    assert codes.CHAIN_GAP_DECLARED in all_codes(result)


def test_absent_file_yields_no_records_and_no_problems(tmp_path):
    result = read_record_file(str(tmp_path / "nothing.jsonl"))
    assert not result.present
    assert result.records == []
    assert result.problems == []


def test_record_hash_ignores_member_order_on_disk(tmp_path):
    # Canonicalization absorbs it, so a tool that reordered members without
    # changing values leaves the record verifying.
    import json

    parsed = json.loads(RECORD_0)
    reordered = json.dumps(dict(sorted(parsed.items(), reverse=True)), separators=(",", ":"))
    assert reordered != RECORD_0
    path = str(tmp_path / "audit.jsonl")
    write_lines(path, [reordered])
    result = read_record_file(path)
    assert fatal_codes(result) == []
    assert result.records[0].hash == HASH_0
