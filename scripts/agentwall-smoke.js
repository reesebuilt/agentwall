#!/usr/bin/env node
// Minimal end-to-end smoke against a running Agentwall instance.
//
// Sends two POST /evaluate requests that stand in for the two planes an agent harness
// hits first: an outbound HTTP call and a shell exec. Prints the raw JSON decisions so
// you can eyeball them, and does not assert -- this is a "is the seam alive" check, not
// the test suite. For pass/fail gating use `npm test` or scripts/security-regression.js.
//
// Usage: node scripts/agentwall-smoke.js [base-url]
// Default base-url matches examples/monitor-first.config.yaml.

const http = require('http');

const baseUrl = process.argv[2] || 'http://127.0.0.1:3015';
const base = new URL(baseUrl);

function post(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      host: base.hostname,
      port: base.port || 80,
      path,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(data),
      },
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(raw || '{}') });
        } catch {
          // Non-JSON bodies are the usual symptom of pointing at the wrong port, so
          // surface the raw text instead of a parse error.
          resolve({ status: res.statusCode, body: raw });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const actor = { channelId: 'telegram:<chat-id>:<thread-id>', userId: 'operator', roleIds: ['owner'] };

(async () => {
  const results = {};

  results.networkEvaluate = await post('/evaluate', {
    agentId: 'agent-1',
    sessionId: 'smoke-network',
    plane: 'network',
    action: 'http_request',
    payload: { url: 'https://api.openai.com/v1/chat/completions', tool: 'web_fetch' },
    actor,
    control: { executionMode: 'normal' },
    provenance: [{ source: 'user', trustLabel: 'trusted' }],
    flow: { direction: 'egress', labels: ['external_egress'], highRisk: true },
  });

  results.toolEvaluate = await post('/evaluate', {
    agentId: 'agent-1',
    sessionId: 'smoke-tool',
    plane: 'tool',
    action: 'bash_exec',
    payload: { command: 'git status' },
    actor,
    control: { executionMode: 'normal' },
    provenance: [{ source: 'user', trustLabel: 'trusted' }],
    flow: { direction: 'internal', labels: ['destructive_action'], highRisk: true },
  });

  console.log(JSON.stringify({ baseUrl, results }, null, 2));
})();
