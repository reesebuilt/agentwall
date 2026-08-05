#!/usr/bin/env bash

set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: sudo ./scripts/agentwall-uninstall.sh [--yes]

Privileged uninstall helper for manual Agentwall deployments.

This script removes common Linux service/config/state artifacts created by a
manual install. It does not remove the cloned source tree or npm dependencies.

Options:
  --yes    Skip the confirmation prompt.
  --help   Show this help text.
EOF
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "This uninstall path requires root. Re-run with sudo or as root." >&2
  exit 1
fi

ASSUME_YES=0
if [[ "${1:-}" == "--yes" ]]; then
  ASSUME_YES=1
elif [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  exit 1
fi

SERVICE_CANDIDATES=(
  "/etc/systemd/system/agentwall.service"
  "/etc/systemd/system/agentwall-server.service"
)

CONFIG_CANDIDATES=(
  "/etc/agentwall"
  "/etc/agentwall/config.yaml"
  "/etc/agentwall/policy.yaml"
)

STATE_CANDIDATES=(
  "/var/lib/agentwall"
  "/var/log/agentwall"
  "/run/agentwall"
)

BIN_CANDIDATES=(
  "/usr/local/bin/agentwall"
)

print_existing_paths() {
  local found=0
  local path
  for path in "$@"; do
    if [[ -e "$path" ]]; then
      echo "  $path"
      found=1
    fi
  done
  return "$found"
}

echo "Agentwall privileged uninstall"
echo "The script will stop known systemd units and remove known Linux service/config/state artifacts if present."
echo
echo "Matching paths:"
print_existing_paths \
  "${SERVICE_CANDIDATES[@]}" \
  "${CONFIG_CANDIDATES[@]}" \
  "${STATE_CANDIDATES[@]}" \
  "${BIN_CANDIDATES[@]}" || true
echo

if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "Continue uninstall? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES)
      ;;
    *)
      echo "Aborted."
      exit 0
      ;;
  esac
fi

remove_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    rm -rf -- "$path"
    echo "Removed $path"
  fi
}

for unit in agentwall.service agentwall-server.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    echo "Stopped/disabled $unit"
  fi
done

for path in "${SERVICE_CANDIDATES[@]}"; do
  remove_path "$path"
done

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

for path in "${CONFIG_CANDIDATES[@]}"; do
  remove_path "$path"
done

for path in "${STATE_CANDIDATES[@]}"; do
  remove_path "$path"
done

for path in "${BIN_CANDIDATES[@]}"; do
  remove_path "$path"
done

echo "Privileged Agentwall artifacts removed where present."
echo "The source checkout under the current workspace was left in place."
