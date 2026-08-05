#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const securityGroups = [
  {
    name: 'Egress protections',
    tests: [
      'tests/ssrf.test.ts',
      'tests/dlp.test.ts',
    ],
  },
  {
    name: 'Integrity and stress controls',
    tests: [
      'tests/manifest.test.ts',
      'tests/floodguard.test.ts',
    ],
  },
  {
    name: 'Approvals and evidence',
    tests: [
      'tests/approval-webhook.test.ts',
      'tests/audit-chain.test.ts',
      'tests/capability-ticket.test.ts',
    ],
  },
  {
    name: 'agent-harness security integrations',
    tests: [
      'tests/agent-harness-preflight.integration.test.ts',
      'tests/agent-harness-observed-web-fetch.integration.test.ts',
    ],
  },
];

function run(command, args, label) {
  console.log(`\n[security-regression] ${label}`);
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: process.env,
    stdio: 'inherit',
  });

  if (result.error) {
    console.error(`[security-regression] ${label} failed to start: ${result.error.message}`);
    process.exit(1);
  }

  if (result.status !== 0) {
    if (result.signal) {
      console.error(`[security-regression] ${label} failed with signal ${result.signal}`);
      process.exit(1);
    }

    console.error(`[security-regression] ${label} failed with exit code ${result.status}`);
    process.exit(result.status || 1);
  }

  console.log(`[security-regression] ${label} passed`);
}

for (const [index, group] of securityGroups.entries()) {
  run(
    npmCommand,
    ['test', '--', '--runInBand', ...group.tests],
    `Group ${index + 1}/${securityGroups.length}: ${group.name}`,
  );
}

run(npmCommand, ['run', 'build'], 'Build verification');
console.log('\n[security-regression] Nightly security regression passed');
