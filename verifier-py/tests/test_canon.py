"""cu1, checked against the worked examples in docs/audit-format.md.

Every constant in this file is copied from the document, so these tests fail
if this implementation drifts from the format rather than from itself.
"""

from __future__ import annotations

import pytest

from agentwall_verify.canon import canon, canonical_payload, embed, hash_material, sha256_hex
from agentwall_verify.tokens import DuplicateKey, JsonError, TruncatedJson, parse, sort_key
from helpers import HASH_0, HASH_1, RECORD_0, RECORD_1


def test_worked_example_payload_and_hash():
    payload = canonical_payload(parse(RECORD_0))
    assert payload == (
        '{"action":"egress:https","agentId":"curl","decision":"allow","highRiskFlow":false,'
        '"id":"01JQ8Z0MZ9V6QK9J0H7X4T2R5B","matchedRules":[],'
        '"metadata":{"durationMs":"378","host":"example.com","port":"443"},"plane":"network",'
        '"reasons":["monitor-first: observed, not gated"],"requiresApproval":false,'
        '"riskLevel":"low","timestamp":"2026-01-01T00:00:00.000Z"}'
    )
    material = hash_material("0", "null", payload)
    assert len(material.encode("utf-8")) == 471
    assert sha256_hex(material) == HASH_0


def test_second_record_folds_in_the_first():
    payload = canonical_payload(parse(RECORD_1))
    material = hash_material("1", '"' + HASH_0 + '"', payload)
    assert sha256_hex(material) == HASH_1


def test_keys_sort_by_utf16_code_unit_not_code_point():
    source = r'{"\uff21":5,"apple":2,"\ud835\udc00":4,"Zebra":1,"\u00c4":3}'
    assert canon(parse(source)) == r'{"Zebra":1,"apple":2,"\u00c4":3,"\ud835\udc00":4,"\uff21":5}'


def test_astral_key_sorts_below_fullwidth_a():
    # U+1D400 has the higher code point and the lower first code unit, because
    # outside the BMP a character leads with a high surrogate in D800..DBFF.
    assert sort_key("\U0001D400") < sort_key("\uFF21")
    assert ord("\U0001D400") > ord("\uFF21")


def test_sorting_uses_decoded_keys_and_emission_uses_written_lexemes():
    # Both keys decode to the same character and are written differently, so a
    # verifier that emitted decoded keys would produce the same bytes for two
    # records that are not the same bytes.
    escaped = canon(parse(r'{"\u00c4":1,"a":2}'))
    literal = canon(parse('{"\u00c4":1,"a":2}'))
    assert escaped == r'{"a":2,"\u00c4":1}'
    assert literal == '{"a":2,"\u00c4":1}'
    assert escaped != literal


def test_numbers_are_reused_never_reformatted():
    # Reserializing would turn these into Python's own spelling and change the
    # hash for a record nobody touched.
    source = '{"a":1e21,"b":-0,"c":1.500,"d":0.1000000000000000055511151231257827}'
    assert canon(parse(source)) == source


def test_string_escapes_are_reused_verbatim():
    source = r'{"a":"\u0041\/\\\"","b":"A"}'
    assert canon(parse(source)) == source


def test_arrays_keep_source_order():
    assert canon(parse('{"a":[3,1,2]}')) == '{"a":[3,1,2]}'


def test_embed_escapes_only_backslash_and_quote():
    assert embed(r'{"a":"b\\c"}') == r'"{\"a\":\"b\\\\c\"}"'


def test_duplicate_key_is_refused_rather_than_resolved():
    with pytest.raises(DuplicateKey) as caught:
        parse('{"a":1,"a":2}')
    assert caught.value.key == "a"


def test_duplicate_key_is_found_at_any_depth():
    with pytest.raises(DuplicateKey):
        parse('{"outer":{"a":1,"a":2}}')


def test_duplicate_key_detected_when_only_the_escaping_differs():
    # The two spellings decode alike, which is exactly the pair a parser would
    # silently collapse.
    with pytest.raises(DuplicateKey):
        parse(r'{"\u00c4":1,"Ä":2}')


def test_truncation_is_distinct_from_other_syntax_errors():
    with pytest.raises(TruncatedJson):
        parse('{"a":1')
    with pytest.raises(TruncatedJson):
        parse('{"a":"unterminated')
    with pytest.raises(TruncatedJson):
        parse('{"a":tru')


def test_trailing_data_is_a_plain_syntax_error():
    with pytest.raises(JsonError) as caught:
        parse('{"a":1} {"b":2}')
    assert not isinstance(caught.value, TruncatedJson)


@pytest.mark.parametrize(
    "source",
    [
        "{'a':1}",
        '{"a":01}',
        '{"a":+1}',
        '{"a":.5}',
        '{"a":1,}',
        '[1,]',
        '{"a":"tab\there"}',
        '{"a":"\\x41"}',
        '{a:1}',
    ],
)
def test_strict_json_only(source):
    with pytest.raises(JsonError):
        parse(source)
