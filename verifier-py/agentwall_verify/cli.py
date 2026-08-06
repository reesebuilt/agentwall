"""Command line surface, matching the Go verifier so one harness drives both.

Exit codes: 0 all layers verified, 1 verification failure or incomplete
evidence, 2 usage or IO error. Nothing here reads the environment, opens a
socket, or writes a file: every check the format defines is computable offline
from the evidence, and a verifier that needed more would be claiming something
the format cannot support.
"""

from __future__ import annotations

import argparse
import os
import sys

from .evidence import Paths, verify
from .report import VERIFIER_NAME, VERIFIER_VERSION, emit

USAGE_EXIT = 2

_EPILOG = """Defaults resolve beside the audit file: segments.jsonl, anchors.jsonl, and proofs/.
Exit codes: 0 all layers verified, 1 verification failure or incomplete evidence, 2 usage or IO error."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=VERIFIER_NAME,
        description="agentwall-verify-py verifies AgentWall audit evidence.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    parser.add_argument("--audit", default="", help="path to the audit JSONL file (required)")
    parser.add_argument("--manifest", default="", help="path to the rotation manifest (default segments.jsonl beside audit)")
    parser.add_argument("--anchors", default="", help="path to the anchor log (default anchors.jsonl beside audit)")
    parser.add_argument("--proofs", default="", help="directory of OTS proof files (default proofs/ beside audit)")
    parser.add_argument("--pubkey", default="", help="base64 SPKI public key to pin checkpoints to")
    parser.add_argument("--pubkey-file", default="", dest="pubkey_file", help="file holding a public key to pin checkpoints to")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human-readable output")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return parser


def main(argv: list[str] | None = None, stdout=None, stderr=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_code:
        # argparse exits 0 for --help and 2 for a usage error; both match the
        # Go verifier's contract, so the code is passed through unchanged.
        return int(exit_code.code or 0)

    if args.version:
        stdout.write(VERIFIER_NAME + " " + VERIFIER_VERSION + "\n")
        return 0

    if not args.audit:
        stderr.write("error: --audit is required\n")
        parser.print_usage(stderr)
        return USAGE_EXIT
    if args.pubkey and args.pubkey_file:
        stderr.write("error: pass at most one of --pubkey or --pubkey-file\n")
        return USAGE_EXIT
    if not os.path.isfile(args.audit):
        stderr.write("error: audit file " + repr(args.audit) + " not found\n")
        return USAGE_EXIT

    pin = args.pubkey
    if args.pubkey_file:
        try:
            pin = open(args.pubkey_file, "r", encoding="utf-8").read().strip()
        except OSError as err:
            stderr.write("error: " + str(err) + "\n")
            return USAGE_EXIT
        if not pin:
            stderr.write("error: " + repr(args.pubkey_file) + " holds no key\n")
            return USAGE_EXIT

    paths = Paths(args.audit, args.manifest, args.anchors, args.proofs)
    try:
        result = verify(paths, pin)
    except OSError as err:
        stderr.write("error: " + str(err) + "\n")
        return USAGE_EXIT

    emit(result, args.json, stdout)
    return 0 if result.ok else 1
