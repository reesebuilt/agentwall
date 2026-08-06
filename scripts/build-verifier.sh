#!/usr/bin/env bash
# Cross-compile the Go verifier into release binaries, reproducibly.
#
# This script exists so that CI and a stranger run the SAME build. The release workflow used to
# carry the build as an inline loop in YAML, and the documented way to reproduce it was to read
# that YAML and retype it. Anything a person retypes drifts, and a reproducibility claim that
# drifts is worse than no claim: it tells a skeptic their correct rebuild is wrong.
#
# Reproducible here means a specific, testable thing: two people who check out the same commit
# get byte-identical output, and their bytes match the release. Each measurement below was taken
# against verifier/ at v0.2.0 with go1.22.12, comparing sha256 of linux/amd64 output.
#
#   -trimpath          Without it the binary embeds the builder's absolute source paths, so a
#                      build from /home/alice differs from one in /build. MEASURED: required.
#
#   -buildvcs=false    This is the one that actually bit us. Go stamps vcs.revision, vcs.time,
#                      and vcs.modified into any main package built inside a git repository.
#                      A release built by actions/checkout therefore embedded a commit hash,
#                      while a stranger rebuilding from the GitHub source tarball (no .git) did
#                      not, and their hashes differed for a reason that had nothing to do with
#                      the source. MEASURED: with stamping on, clone and tarball builds differ
#                      (63f87a12... vs 71de4b66...); with it off, a git worktree, a full clone,
#                      and a .git-less copy at a different path all produce 71de4b66....
#
#                      Nothing is lost by dropping the stamp. The commit is recorded in the SLSA
#                      provenance attached to the release, which is signed and therefore stronger
#                      evidence than a string the binary reports about itself, and the release
#                      version is stamped explicitly via -ldflags below.
#
#   GOAMD64=v1         Go honours GOAMD64 from the environment and it changes code generation.
#                      MEASURED: v3 produces 5281b668..., v1 produces 71de4b66.... A developer
#                      who exports GOAMD64=v3 for their own machine would otherwise fail to
#                      reproduce a correct release. Irrelevant to the arm64 targets, harmless
#                      there, so it is set once rather than conditionally.
#
#   GOEXPERIMENT=      Also honoured from the environment and also changes codegen. MEASURED:
#                      GOEXPERIMENT=loopvar produces 2c7b9e44.... Cleared, not inherited.
#
#   GOFLAGS=           Cleared so an exported GOFLAGS cannot inject a build flag we did not
#                      choose. GOFLAGS=-race in the caller's environment is enough to change the
#                      output of every command below.
#
#   CGO_ENABLED=0      Static binaries, so the verifier runs on a machine with no toolchain and
#                      no libc of a particular vintage. Also removes the host C compiler as a
#                      build input, which is not reproducible across distributions.
#
#   GOTOOLCHAIN=local  Refuse to silently download a different toolchain. The Go version changes
#                      the output bytes, so an automatic upgrade would break reproduction
#                      quietly. That is also why GO_VERSION below is exact rather than a range,
#                      and why the version check is fatal by default.
#
# The build cache does not affect output: MEASURED identical from a cold GOCACHE.
#
# Usage:
#   scripts/build-verifier.sh <version> <output-dir>
#   scripts/build-verifier.sh --print-go-version
#
# Env:
#   AGENTWALL_ALLOW_GO_MISMATCH=1  Build with a Go other than GO_VERSION. The output will not
#                                  match the release; useful only for local experiments.

set -euo pipefail

# The single source of truth for the release toolchain. The release workflow reads this value via
# --print-go-version and feeds it to actions/setup-go, so CI cannot pin one Go while this script
# demands another. verifier/go.mod's `go 1.22` is a language-version floor and deliberately not
# this number: it answers "what does the source require", not "what produced the release bytes".
GO_VERSION="1.22.12"

# GOOS/GOARCH pairs to ship. windows/amd64 is built and checksummed but is not offered through
# Homebrew, which has no Windows support.
TARGETS=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

if [ "${1:-}" = "--print-go-version" ]; then
  printf '%s\n' "$GO_VERSION"
  exit 0
fi

if [ "$#" -ne 2 ]; then
  echo "usage: scripts/build-verifier.sh <version> <output-dir>" >&2
  echo "       scripts/build-verifier.sh --print-go-version" >&2
  exit 2
fi

version="$1"
outdir="$2"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v go >/dev/null 2>&1; then
  echo "no 'go' on PATH. This script needs Go ${GO_VERSION} to produce release-identical bytes." >&2
  echo "Install it from https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz (adjust for your platform)." >&2
  exit 1
fi

# `go version` prints "go version go1.22.12 linux/amd64". Compare the exact patch release: a
# mismatch here is the most likely reason a rebuild does not match, and finding out via a
# checksum mismatch teaches the reader nothing about why.
have_go="$(go version | awk '{print $3}' | sed 's/^go//')"
if [ "$have_go" != "$GO_VERSION" ]; then
  if [ "${AGENTWALL_ALLOW_GO_MISMATCH:-}" = "1" ]; then
    echo "WARNING: building with go ${have_go}, but the release used go ${GO_VERSION}." >&2
    echo "WARNING: the resulting binaries will NOT match the published checksums." >&2
  else
    echo "this Go is ${have_go}; the release was built with ${GO_VERSION}." >&2
    echo "Different Go versions emit different bytes, so a rebuild with ${have_go} cannot match" >&2
    echo "the published checksums. Install go${GO_VERSION}, or set" >&2
    echo "AGENTWALL_ALLOW_GO_MISMATCH=1 to build anyway and accept a mismatch." >&2
    exit 1
  fi
fi

mkdir -p "$outdir"
# Absolute, because the build below runs from verifier/ and a relative outdir would land inside it.
outdir="$(cd "$outdir" && pwd)"

echo "building agentwall-verify ${version} with go ${have_go}"

names=()
for target in "${TARGETS[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  [ "$goos" = "windows" ] && ext=".exe"
  name="agentwall-verify-${goos}-${goarch}${ext}"
  output="${outdir}/${name}"

  # `env -i` is deliberately not used: the build needs PATH, HOME (for GOCACHE and GOMODCACHE),
  # and on some systems TMPDIR. Every variable that was measured to change the output is set
  # explicitly here instead, which covers the same ground without guessing at the rest.
  ( cd "${repo_root}/verifier" && env \
      CGO_ENABLED=0 \
      GOOS="$goos" \
      GOARCH="$goarch" \
      GOAMD64=v1 \
      GOEXPERIMENT= \
      GOFLAGS= \
      GOTOOLCHAIN=local \
      go build \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -X main.verifierVersion=${version}" \
        -o "$output" \
        . )

  names+=("$name")
  echo "  ${name}"
done

# One line per binary, in the format `sha256sum -c` and `shasum -a 256 -c` both read, sorted with
# a fixed collation so the file is byte-identical across runs of the same inputs.
#
# Two portability points, both of which broke this script on macOS before they were fixed, and
# macOS matters here because two of the five targets are darwin and the documented way to check a
# darwin binary is to rebuild it on a Mac:
#
#   - The file list is accumulated in the loop above rather than recovered afterwards with
#     `find -printf`. -printf is a GNU extension; BSD find, which is what macOS ships, does not
#     have it and exits with a usage error before a single digest is printed.
#   - Stock macOS has no sha256sum. It ships `shasum`, a Perl script, whose `-a 256` output format
#     is byte-identical to sha256sum's, so the manifest a Mac produces is directly comparable to
#     the one the Linux release runner produces. That equivalence is the only reason this fallback
#     is acceptable rather than a second, subtly different manifest format.
sha_cmd=(sha256sum)
if ! command -v sha256sum >/dev/null 2>&1; then
  if command -v shasum >/dev/null 2>&1; then
    sha_cmd=(shasum -a 256)
  else
    echo "neither sha256sum nor shasum is available, so the manifest cannot be written." >&2
    echo "The binaries above were built and are in ${outdir}." >&2
    exit 1
  fi
fi

# `sort` is POSIX and present on macOS; the GNU-only pieces are the two above. Names are fixed
# ASCII with no spaces, so a plain xargs is safe here.
( cd "$outdir" && printf '%s\n' "${names[@]}" \
    | LC_ALL=C sort \
    | xargs "${sha_cmd[@]}" > SHA256SUMS-verifier.txt )

cat "${outdir}/SHA256SUMS-verifier.txt"
