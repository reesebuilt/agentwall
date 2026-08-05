#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

DASHBOARD_URL="${AGENTWALL_DASHBOARD_URL:-http://127.0.0.1:3000/api/dashboard/state}"
ORG_URL="${AGENTWALL_ORG_URL:-http://127.0.0.1:3015/api/org/summary}"
SERVICE_NAME="${AGENTWALL_SERVICE_NAME:-agentwall-live.service}"

printf '[Agentwall] focused dashboard/org tests\n'
npm test -- --runTestsByPath tests/dashboard.test.ts tests/org-control-plane.test.ts --runInBand

printf '[Agentwall] lint\n'
npm run lint

printf '[Agentwall] build\n'
npm run build

if command -v systemctl >/dev/null 2>&1 && systemctl --user show "$SERVICE_NAME" >/dev/null 2>&1; then
  printf '[Agentwall] restart %s\n' "$SERVICE_NAME"
  systemctl --user restart "$SERVICE_NAME"
  systemctl --user show "$SERVICE_NAME" -p ActiveState -p SubState -p MainPID -p NRestarts --no-pager
else
  printf '[Agentwall] service %s not available; skipping restart\n' "$SERVICE_NAME"
fi

printf '[Agentwall] live API verification\n'
python3 - <<'PY'
import json
import os
import sys
import time
import urllib.request

DASHBOARD_URL = os.environ.get('AGENTWALL_DASHBOARD_URL', 'http://127.0.0.1:3000/api/dashboard/state')
ORG_URL = os.environ.get('AGENTWALL_ORG_URL', 'http://127.0.0.1:3015/api/org/summary')

def fetch_json(url, attempts=20):
    last = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status != 200:
                    raise RuntimeError(f'{url} returned HTTP {response.status}')
                return json.load(response)
        except Exception as exc:
            last = exc
            time.sleep(0.5)
    raise RuntimeError(f'failed to fetch {url}: {last}')

dashboard = fetch_json(DASHBOARD_URL)
org = fetch_json(ORG_URL)

def require(condition, message):
    if not condition:
        raise AssertionError(message)

require(dashboard.get('brand') == 'Agentwall', 'dashboard brand is not Agentwall')
require(dashboard.get('generatedAt'), 'dashboard generatedAt missing')
require((dashboard.get('controls') or {}).get('egress', {}).get('defaultDeny') is True, 'egress.defaultDeny is not true')
require(org.get('ok') is True, 'org summary ok is not true')
require(org.get('schemaVersion') == 'agentwall.org.summary.v1', 'unexpected org summary schema')

text = json.dumps(dashboard, sort_keys=True)

# The dashboard reports that the agent's prompt/profile/env files exist, and must never
# echo their contents. These markers are the cheap tripwire for that. 'You are ' catches a
# system prompt, 'USER PROFILE' a profile section header, the rest are direct secret and
# source-map bleed. Your own agent's prompt header is operator-specific and must not be
# committed here, so add it at run time via AGENTWALL_LEAK_MARKERS (comma-separated).
markers = ['USER PROFILE', 'You are ', 'TELEGRAM_BOT_TOKEN=', 'BEGIN PRIVATE KEY', 'sourceMappingURL']
markers += [m.strip() for m in os.environ.get('AGENTWALL_LEAK_MARKERS', '').split(',') if m.strip()]
for marker in markers:
    require(marker not in text, f'leak marker present in dashboard payload: {marker}')

print(json.dumps({
    'dashboard_ok': True,
    'service_status': (dashboard.get('service') or {}).get('status'),
    'attention_required': (dashboard.get('service') or {}).get('attentionRequired'),
    'default_deny': (dashboard.get('controls') or {}).get('egress', {}).get('defaultDeny'),
    'org_ok': org.get('ok'),
}, indent=2, sort_keys=True))
PY

printf '[Agentwall] live verification complete\n'
