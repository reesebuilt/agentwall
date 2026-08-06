#!/usr/bin/env node
// Generate the Homebrew formula for agentwall-verify from a real checksum manifest.
//
// The formula is GENERATED, never hand-written and never committed with checksums in it. A
// committed formula carries the digests of whatever release existed when someone last edited it,
// and the failure mode is silent: `brew install` fetches the current asset, compares it against a
// stale digest, and tells the user the download is corrupt. Deriving the digests from the same
// manifest that `sha256sum -c` reads means the formula cannot disagree with the release, because
// there is only one place the numbers come from.
//
// That also gives a skeptic something to check. Every sha256 the generated formula declares
// appears verbatim in checksums.txt on the release page, so the formula can be audited against
// the manifest without trusting this script:
//
//   sed -n 's/.*sha256 "\([0-9a-f]\{64\}\)".*/\1/p' agentwall-verify.rb | sort > /tmp/formula
//   grep -F agentwall-verify checksums.txt | cut -d' ' -f1 | sort > /tmp/manifest
//   comm -23 /tmp/formula /tmp/manifest   # empty means the formula declares nothing invented
//
// Match the `sha256 "..."` declarations, not any 64-character hex run: the formula's test block
// embeds an all-zero prevHash, and a bare hex match reports that as an invented digest.
//
// Usage:
//   node scripts/brew-formula.js --version <v> --checksums <file> [--out <file>]
//
// Reads any sha256sum-format manifest, so it works against the release's checksums.txt or the
// verifier-only SHA256SUMS-verifier.txt that scripts/build-verifier.sh writes. Prints to stdout
// when --out is omitted.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const REPO = 'repsecure/agentwall';
const FORMULA_CLASS = 'AgentwallVerify';

// Homebrew supports macOS and Linux only. windows/amd64 is built and checksummed by the release,
// and is deliberately absent here rather than mapped to nothing.
//
// Each entry is a platform branch in the formula. `os` and `cpu` name the Homebrew DSL blocks;
// `asset` is the release asset the branch downloads. A platform whose asset is missing from the
// manifest is a hard failure: a formula that omits a branch installs cleanly and provides no
// binary on that platform, which is the kind of hole that reaches a user instead of a build log.
const PLATFORMS = [
  { os: 'macos', cpu: 'arm', asset: 'agentwall-verify-darwin-arm64' },
  { os: 'macos', cpu: 'intel', asset: 'agentwall-verify-darwin-amd64' },
  { os: 'linux', cpu: 'arm', asset: 'agentwall-verify-linux-arm64' },
  { os: 'linux', cpu: 'intel', asset: 'agentwall-verify-linux-amd64' },
];

function parseArgs(argv) {
  const args = { version: null, checksums: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const take = () => {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`${flag} needs a value`);
      }
      i += 1;
      return value;
    };
    if (flag === '--version') args.version = take();
    else if (flag === '--checksums') args.checksums = take();
    else if (flag === '--out') args.out = take();
    else throw new Error(`unknown argument: ${flag}`);
  }
  if (!args.version) throw new Error('--version is required');
  if (!args.checksums) throw new Error('--checksums is required');
  return args;
}

// sha256sum output is "<64 hex><two spaces><name>", where the second space is a space for text
// mode and an asterisk for binary mode. Both are accepted; anything else is not a line this
// tool should be guessing about.
function parseChecksums(text) {
  const digests = new Map();
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '') continue;
    const match = /^([0-9a-f]{64})\s[\s*]?(.+)$/.exec(line);
    if (!match) {
      throw new Error(`checksums line ${i + 1} is not sha256sum format: ${line}`);
    }
    // Manifests are written from inside the staging directory, so names are bare. Strip any
    // leading path anyway so a manifest produced from a parent directory still resolves.
    digests.set(path.basename(match[2].trim()), match[1]);
  }
  if (digests.size === 0) throw new Error('checksums file lists no files');
  return digests;
}

function buildFormula({ version, digests }) {
  const missing = PLATFORMS.filter((p) => !digests.has(p.asset)).map((p) => p.asset);
  if (missing.length > 0) {
    throw new Error(
      `the checksum manifest has no entry for: ${missing.join(', ')}. ` +
        'Refusing to emit a formula that installs nothing on those platforms.'
    );
  }

  const base = `https://github.com/${REPO}/releases/download/v${version}`;
  const branch = (os, cpu, indent) => {
    const p = PLATFORMS.find((x) => x.cpu === cpu && x.os === os);
    return [
      `${indent}on_${cpu} do`,
      `${indent}  url "${base}/${p.asset}"`,
      `${indent}  sha256 "${digests.get(p.asset)}"`,
      `${indent}end`,
    ].join('\n');
  };
  const platformBlock = (os) =>
    [`  on_${os} do`, branch(os, 'arm', '    '), branch(os, 'intel', '    '), '  end'].join('\n');

  return `# Generated by scripts/brew-formula.js from the v${version} release checksums.
# Do not edit by hand: every sha256 below is copied from that release's checksum manifest, and
# an edit here silently disagrees with the artifact it claims to describe.
class ${FORMULA_CLASS} < Formula
  desc "Independent verifier for Agentwall tamper-evident audit chains"
  homepage "https://github.com/${REPO}"
  version "${version}"
  license "Apache-2.0"

  # Prebuilt, statically linked binaries. The version cannot be inferred from these URLs because
  # the assets are bare executables with no version in the filename, so it is declared above.
${platformBlock('macos')}
${platformBlock('linux')}

  def install
    # The staged filename is the asset name from the URL, which differs per platform, so the
    # binary is found by glob rather than named. Homebrew stages a plain HTTP download with the
    # mode curl left on it, which is not executable, hence the explicit chmod: without it the
    # install succeeds and every later invocation is "permission denied".
    binary = Dir["agentwall-verify-*"].first
    odie "no agentwall-verify binary was staged for this platform" if binary.nil?
    chmod 0755, binary
    bin.install binary => "agentwall-verify"
  end

  test do
    # Two assertions, because either one alone passes on a broken install. The first proves the
    # binary runs on this platform and reports the version the formula claims, which catches a
    # wrong-architecture asset and a stale checksum pointing at an older release.
    assert_match "agentwall-verify #{version}", shell_output("#{bin}/agentwall-verify --version")

    # The second proves it actually verifies, rather than merely starting. A one-record chain
    # whose hashes are wrong must be rejected with a non-zero exit; a verifier that accepted this
    # would pass a --version-only test while being useless.
    (testpath/"broken.jsonl").write <<~JSONL
      {"seq":1,"prevHash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"not-a-real-hash"}
    JSONL
    output = shell_output("#{bin}/agentwall-verify --audit #{testpath}/broken.jsonl --json", 1)
    assert_match(/"ok":\\s*false/, output)
  end
end
`;
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    console.error(
      'usage: node scripts/brew-formula.js --version <v> --checksums <file> [--out <file>]'
    );
    process.exit(2);
  }

  let formula;
  try {
    const digests = parseChecksums(fs.readFileSync(args.checksums, 'utf8'));
    formula = buildFormula({ version: args.version, digests });
  } catch (error) {
    console.error(`cannot generate formula: ${error.message}`);
    process.exit(1);
  }

  if (args.out) {
    fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
    fs.writeFileSync(args.out, formula);
    console.error(`wrote ${args.out}`);
  } else {
    process.stdout.write(formula);
  }
}

if (require.main === module) main();

module.exports = { parseChecksums, buildFormula, PLATFORMS };
