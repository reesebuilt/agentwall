#!/usr/bin/env bash
#
# Compile the Landlock/seccomp launcher.
#
# This is a separate step from `npm run build` on purpose. `build` is `tsc`, `prepack` runs
# `build`, and a packaging host without a C compiler would then fail to publish a package whose
# TypeScript is perfectly fine. Compiling the helper is also the moment an operator decides to
# trust a binary that will hold the filesystem boundary for their agent, and that decision should
# be a command they typed rather than a side effect of installing a dependency.
#
# Output: dist/native/agentwall-sandbox. Exit 0 only if the binary was produced AND answered
# --probe, because a helper that builds but cannot run is not a helper.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC="native/agentwall-sandbox.c"
OUT_DIR="${AGENTWALL_SANDBOX_OUT_DIR:-dist/native}"
OUT="${OUT_DIR}/agentwall-sandbox"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build-sandbox-helper: Landlock and seccomp are Linux kernel features and this host is" >&2
  echo "  $(uname -s). There is nothing to build here, and agentwall sandbox will refuse to run" >&2
  echo "  rather than pretend. See docs/sandbox.md for what is and is not portable." >&2
  exit 1
fi

CC_BIN="${CC:-cc}"
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
  echo "build-sandbox-helper: no C compiler found (tried '${CC_BIN}')." >&2
  echo "  Install one, for example: sudo apt-get install build-essential" >&2
  echo "  Or set CC to the compiler you want used." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

# -static-pie is deliberately not used. The helper must run on the host it was built for, and a
# dynamically linked binary that fails to find its loader fails loudly at exec rather than
# silently doing the wrong thing. The hardening flags below are the standard set; -Werror is on
# because a warning in the code that decides what an agent may read is not a warning worth
# tolerating.
"$CC_BIN" \
  -std=c11 -O2 \
  -Wall -Wextra -Werror \
  -D_FORTIFY_SOURCE=2 \
  -fstack-protector-strong \
  -fPIE -pie \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -o "$OUT" "$SRC"

chmod 0755 "$OUT"

# Prove the thing runs before claiming success. --probe touches nothing and needs no privilege.
if ! PROBE_OUT="$("$OUT" --probe 2>&1)"; then
  echo "build-sandbox-helper: ${OUT} was produced but --probe failed:" >&2
  echo "$PROBE_OUT" >&2
  exit 1
fi

echo "build-sandbox-helper: built ${OUT}"
echo "$PROBE_OUT" | sed 's/^/  /'

# The measured ABI decides what the operator actually gets. Say so here rather than leaving them
# to discover it the first time a rule silently does not apply.
ABI="$(printf '%s\n' "$PROBE_OUT" | sed -n 's/^landlock_abi=//p')"
if [[ "${ABI:-0}" == "0" ]]; then
  echo "build-sandbox-helper: WARNING. This kernel reports no Landlock. The helper is built and" >&2
  echo "  will run, but it will REFUSE to launch a command unless the profile says" >&2
  echo "  allow-degraded, because there would be no filesystem confinement to install." >&2
elif [[ "$ABI" -lt 4 ]]; then
  echo "build-sandbox-helper: note. Landlock ABI ${ABI} is below 4, so TCP port confinement is" >&2
  echo "  unavailable on this kernel (it needs Linux 6.7). Filesystem confinement still applies." >&2
fi
