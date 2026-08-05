#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'USAGE'
Usage: ./scripts/agentwall-install.sh [--prefix DIR] [--yes]

Installs a local Agentwall launcher and (optionally) starter config.
No root required unless your prefix needs it.

Options:
  --prefix DIR  Install location for agentwall launcher (default: /usr/local/bin)
  --yes         Skip prompts and use defaults
  --help        Show this help
USAGE
  exit 0
fi

PREFIX="/usr/local/bin"
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$PREFIX/agentwall"

if [[ ! -f "$REPO_ROOT/dist/cli.js" ]]; then
  echo "Building Agentwall..."
  (cd "$REPO_ROOT" && npm run build)
fi

if [[ "$ASSUME_YES" -ne 1 ]]; then
  echo "Install launcher to: $TARGET"
  read -r -p "Continue? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

mkdir -p "$PREFIX"
cat > "$TARGET" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
node "$REPO_ROOT/dist/cli.js" "\$@"
SCRIPT
chmod +x "$TARGET"

echo "Installed Agentwall launcher: $TARGET"
echo "Try: agentwall help"
