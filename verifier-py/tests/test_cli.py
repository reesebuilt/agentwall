"""The CLI contract, and the whole corpus end to end.

The corpus test is the one that matters most: it is the same 26 cases the
conformance harness drives, checked against the format's expected.json rather
than against this verifier's own opinion.
"""

from __future__ import annotations

import io
import json
import os
import shutil

import pytest

from agentwall_verify.cli import main

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.normpath(os.path.join(HERE, "..", "..", "verifier", "testdata", "corpus"))


def run(argv, cwd=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        code = main(argv, stdout, stderr)
    finally:
        os.chdir(previous)
    return code, stdout.getvalue(), stderr.getvalue()


def corpus_cases():
    if not os.path.isdir(CORPUS):
        return []
    return sorted(name for name in os.listdir(CORPUS) if os.path.isdir(os.path.join(CORPUS, name)))


@pytest.mark.skipif(not corpus_cases(), reason="corpus not present")
@pytest.mark.parametrize("case", corpus_cases())
def test_corpus_case_matches_the_format(case, tmp_path):
    # Copied first: a verifier may create a key file or a lock as a side
    # effect, and the corpus in git is immutable.
    work = str(tmp_path / case)
    shutil.copytree(os.path.join(CORPUS, case), work)
    expected = json.load(open(os.path.join(CORPUS, case, "expected.json")))

    argv = ["--audit", "audit.jsonl", "--json"]
    if os.path.exists(os.path.join(work, "pubkey.txt")):
        argv += ["--pubkey-file", "pubkey.txt"]
    code, out, _ = run(argv, cwd=work)

    report = json.loads(out)
    layers = {layer["name"]: layer["ok"] for layer in report["layers"]}
    assert code == expected["exit"], out
    assert layers == expected["layers"], out


def test_json_report_carries_the_contract_fields(tmp_path):
    work = str(tmp_path / "g4")
    shutil.copytree(os.path.join(CORPUS, "g4-anchored-pending"), work)
    _, out, _ = run(["--audit", "audit.jsonl", "--json"], cwd=work)
    report = json.loads(out)
    assert [layer["name"] for layer in report["layers"]] == ["chained", "linked", "anchored"]
    for counter in ("pending", "confirmed", "failed"):
        assert isinstance(report[counter], int)
    assert report["verifier"]["language"] == "python"
    assert report["verifier"]["canon"] == "cu1"


def test_a_pending_attestation_is_reported_as_pending_never_as_proof(tmp_path):
    work = str(tmp_path / "g4")
    shutil.copytree(os.path.join(CORPUS, "g4-anchored-pending"), work)
    _, out, _ = run(["--audit", "audit.jsonl", "--json"], cwd=work)
    report = json.loads(out)
    assert [entry["kind"] for entry in report["attestations"]] == ["pending"]
    assert report["attestations"][0]["calendar"].startswith("https://")
    assert "height" not in report["attestations"][0]


def test_a_bitcoin_attestation_is_a_value_and_a_height_to_compare_elsewhere(tmp_path):
    work = str(tmp_path / "g6")
    shutil.copytree(os.path.join(CORPUS, "g6-anchor-bitcoin-attestation"), work)
    code, out, _ = run(["--audit", "audit.jsonl"], cwd=work)
    assert code == 0
    assert "compare it with a Bitcoin source" in out
    # The prose must not claim the anchor proves when this history existed.
    assert "until a Bitcoin attestation is compared with a block source" in out


def test_pinning_a_foreign_key_fails_where_self_consistency_passes(tmp_path):
    work = str(tmp_path / "b8")
    shutil.copytree(os.path.join(CORPUS, "b8-checkpoint-foreign-key"), work)
    pinned, out, _ = run(["--audit", "audit.jsonl", "--json", "--pubkey-file", "pubkey.txt"], cwd=work)
    assert pinned == 1
    assert "checkpoint-key-mismatch" in out
    # Without the pin, a checkpoint signed by a forger's own key verifies
    # against the key it carries. That is the limit, not a bug.
    _, unpinned, _ = run(["--audit", "audit.jsonl", "--json"], cwd=work)
    assert "checkpoint-key-mismatch" not in unpinned


def test_missing_audit_argument_is_a_usage_error():
    code, _, err = run([])
    assert code == 2
    assert "--audit is required" in err


def test_absent_audit_file_is_a_usage_error(tmp_path):
    code, _, err = run(["--audit", str(tmp_path / "nope.jsonl")])
    assert code == 2
    assert "not found" in err


def test_two_pins_are_a_usage_error(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("\n")
    code, _, err = run(["--audit", str(path), "--pubkey", "x", "--pubkey-file", "y"])
    assert code == 2
    assert "at most one" in err


def test_version_exits_zero_without_reading_evidence():
    code, out, _ = run(["--version"])
    assert code == 0
    assert out.startswith("agentwall-verify-py ")


def test_a_relative_manifest_path_verifies_from_any_directory(tmp_path):
    # The same evidence must verify from anywhere, or the verdict becomes a
    # property of the operator's shell.
    work = str(tmp_path / "g3")
    shutil.copytree(os.path.join(CORPUS, "g3-rotated-segments"), work)
    inside, from_inside, _ = run(["--audit", "audit.jsonl", "--json"], cwd=work)
    outside, from_outside, _ = run(["--audit", os.path.join(work, "audit.jsonl"), "--json"], cwd=str(tmp_path))
    assert inside == outside
    left = {layer["name"]: layer["ok"] for layer in json.loads(from_inside)["layers"]}
    right = {layer["name"]: layer["ok"] for layer in json.loads(from_outside)["layers"]}
    assert left == right
