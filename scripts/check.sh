#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo '[Agentwall] lint'
npm run lint

echo '[Agentwall] tests'
npm test

echo '[Agentwall] build'
npm run build

echo '[Agentwall] check complete'
