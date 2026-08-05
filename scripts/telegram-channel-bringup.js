#!/usr/bin/env node
// Telegram topic bringup helper for the local Agentwall dashboard API.
// Sets the channel-firewall profile for a single (agentId, telegram topic) lane,
// then runs the platform-neutral communication-channel proof suite and prints
// a concise human-readable summary. Exits non-zero if any required check fails.
//
// No secrets are required and none are logged. Every request goes to your local
// Agentwall dashboard, never to Telegram, so the defaults are safe to run as-is.
//
// The default chat id is Telegram's documentation placeholder, not a real chat. Pass
// --chat-id / --thread-id (or the env vars below) with the ids of the topic you actually
// want under containment. Treat those ids as sensitive: do not commit them.

const http = require('http');
const https = require('https');
const { URL } = require('url');

const DEFAULTS = {
  agentId: process.env.AGENTWALL_AGENT_ID || 'agent-1',
  platform: 'telegram',
  chatId: process.env.AGENTWALL_TELEGRAM_CHAT_ID || '-1001234567890',
  threadId: process.env.AGENTWALL_TELEGRAM_THREAD_ID || '4242',
  baseUrl: process.env.AGENTWALL_DASHBOARD_BASE_URL || 'http://127.0.0.1:3015',
  profile: 'answer_only',
};

function printHelp() {
  process.stdout.write(`Usage: node scripts/telegram-channel-bringup.js [options]

Brings up a single Telegram topic on the local Agentwall dashboard:
  1. POST /api/dashboard/control/channel-firewall-profile -> profile (default: answer_only)
  2. POST /api/dashboard/proof/communication-channel       -> guardrail proof suite

Options:
  --agent-id <id>       Agentwall agentId for the lane (default: ${DEFAULTS.agentId})
  --chat-id <id>        Telegram chat id, negative for supergroups (default: ${DEFAULTS.chatId})
  --thread-id <id>      Telegram message_thread_id (default: ${DEFAULTS.threadId})
  --platform <name>     Communication-channel platform (default: ${DEFAULTS.platform})
  --profile <name>      Channel-firewall profile to set (default: ${DEFAULTS.profile})
                        One of: observe, answer_only, read_only, approval_required, locked_down
  --base-url <url>      Dashboard base URL (default: ${DEFAULTS.baseUrl})
  --no-set-profile      Skip the profile set; only run the proof suite
  --dry-run             Print the planned requests and exit without sending them
  --json                Print the raw proof response as JSON instead of a summary
  -h, --help            Show this help

Environment overrides:
  AGENTWALL_AGENT_ID, AGENTWALL_TELEGRAM_CHAT_ID, AGENTWALL_TELEGRAM_THREAD_ID,
  AGENTWALL_DASHBOARD_BASE_URL

Exit codes:
  0  proof suite passed (all required checks passed)
  1  proof suite returned attention status (a required check failed)
  2  CLI usage or transport error
`);
}

function parseArgs(argv) {
  const opts = {
    agentId: DEFAULTS.agentId,
    platform: DEFAULTS.platform,
    chatId: DEFAULTS.chatId,
    threadId: DEFAULTS.threadId,
    baseUrl: DEFAULTS.baseUrl,
    profile: DEFAULTS.profile,
    setProfile: true,
    dryRun: false,
    json: false,
    help: false,
  };

  const stringFlags = {
    '--agent-id': 'agentId',
    '--chat-id': 'chatId',
    '--thread-id': 'threadId',
    '--platform': 'platform',
    '--profile': 'profile',
    '--base-url': 'baseUrl',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      opts.help = true;
      continue;
    }
    if (arg === '--no-set-profile') {
      opts.setProfile = false;
      continue;
    }
    if (arg === '--dry-run') {
      opts.dryRun = true;
      continue;
    }
    if (arg === '--json') {
      opts.json = true;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(stringFlags, arg)) {
      const next = argv[i + 1];
      if (typeof next !== 'string' || next.startsWith('--')) {
        throw new Error(`Flag ${arg} requires a value`);
      }
      opts[stringFlags[arg]] = next;
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return opts;
}

function buildChannelId(opts) {
  const trimmedChat = String(opts.chatId).trim();
  const trimmedThread = String(opts.threadId).trim();
  if (!trimmedChat) throw new Error('chat-id is required');
  if (!trimmedThread) throw new Error('thread-id is required');
  if (opts.platform !== 'telegram') {
    return `${opts.platform}:${trimmedChat}:${trimmedThread}`;
  }
  const base = trimmedChat.startsWith('telegram:') ? trimmedChat : `telegram:${trimmedChat}`;
  if (base.split(':').length >= 3) return base;
  return `${base}:${trimmedThread}`;
}

function postJson(baseUrl, path, body) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(path, baseUrl);
    } catch (err) {
      reject(new Error(`Invalid base-url + path: ${err.message}`));
      return;
    }
    const transport = target.protocol === 'https:' ? https : http;
    const data = Buffer.from(JSON.stringify(body));
    const req = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname}${target.search || ''}`,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': data.length,
      },
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        let parsed;
        try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = raw; }
        resolve({ status: res.statusCode || 0, body: parsed });
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function summarizeProof(proof) {
  const lines = [];
  const target = proof.target || {};
  lines.push(`channelId: ${target.channelId}`);
  lines.push(`agentId: ${target.agentId}`);
  lines.push(`profile: ${proof._profileApplied || '(not set this run)'}`);
  const summary = proof.summary || {};
  lines.push(`proof: ${summary.status} (${summary.passedCount}/${summary.total})`);
  lines.push(`proofId: ${proof.proofId}`);
  for (const check of proof.checks || []) {
    const flag = check.passed ? 'PASS' : (check.required ? 'FAIL' : 'warn');
    lines.push(`  - ${flag} ${check.id} expected=${check.expected} got=${check.decision} audit=${check.auditEventId}`);
  }
  return lines.join('\n');
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    printHelp();
    process.exit(2);
  }

  if (opts.help) {
    printHelp();
    return;
  }

  let channelId;
  try {
    channelId = buildChannelId(opts);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(2);
  }

  const profileBody = { agentId: opts.agentId, channelId, profile: opts.profile };
  const proofBody = {
    agentId: opts.agentId,
    platform: opts.platform,
    channelId,
    threadId: opts.threadId,
  };

  if (opts.dryRun) {
    process.stdout.write(`DRY RUN
base-url: ${opts.baseUrl}
${opts.setProfile ? `POST /api/dashboard/control/channel-firewall-profile ${JSON.stringify(profileBody)}\n` : 'profile-set: skipped\n'}POST /api/dashboard/proof/communication-channel ${JSON.stringify(proofBody)}\n`);
    return;
  }

  let appliedProfile = null;
  if (opts.setProfile) {
    let res;
    try {
      res = await postJson(opts.baseUrl, '/api/dashboard/control/channel-firewall-profile', profileBody);
    } catch (err) {
      process.stderr.write(`profile-set transport error: ${err.message}\n`);
      process.exit(2);
    }
    if (res.status !== 200 || !res.body || res.body.ok !== true) {
      process.stderr.write(`profile-set failed: HTTP ${res.status} ${typeof res.body === 'string' ? res.body : JSON.stringify(res.body)}\n`);
      process.exit(2);
    }
    appliedProfile = (res.body.lane && res.body.lane.profile) || opts.profile;
  }

  let proofRes;
  try {
    proofRes = await postJson(opts.baseUrl, '/api/dashboard/proof/communication-channel', proofBody);
  } catch (err) {
    process.stderr.write(`proof transport error: ${err.message}\n`);
    process.exit(2);
  }

  if (proofRes.status !== 200 || !proofRes.body || proofRes.body.ok !== true) {
    process.stderr.write(`proof failed: HTTP ${proofRes.status} ${typeof proofRes.body === 'string' ? proofRes.body : JSON.stringify(proofRes.body)}\n`);
    process.exit(2);
  }

  const proof = proofRes.body;
  proof._profileApplied = appliedProfile;

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(proof, null, 2)}\n`);
  } else {
    process.stdout.write(`${summarizeProof(proof)}\n`);
  }

  const status = (proof.summary && proof.summary.status) || 'attention';
  process.exit(status === 'passed' ? 0 : 1);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`unexpected error: ${err && err.message ? err.message : err}\n`);
    process.exit(2);
  });
}

module.exports = { parseArgs, buildChannelId, summarizeProof, DEFAULTS };
