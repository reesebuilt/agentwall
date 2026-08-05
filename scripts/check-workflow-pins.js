#!/usr/bin/env node
// Fails when a workflow can run code we did not review, or holds a token we did not grant.
//
// Two lexical facts about .github/workflows/*.yml decide both:
//
//   1. `uses: owner/repo@v4` resolves a MUTABLE git ref at run time. Whoever controls that
//      repository can repoint the tag at any commit, and the next run executes it inside our
//      job with our GITHUB_TOKEN and our secrets. A 40-character commit SHA names immutable
//      content, so the code that ran yesterday is the code that runs today. This matters more
//      here than in most repositories: AgentWall's product is evidence about what an agent
//      did, and evidence produced by a build we cannot pin is not evidence.
//
//   2. A workflow with no top-level `permissions:` block inherits the repository default
//      token scope. On repositories created before GitHub changed the default, and on any
//      repository where an admin sets it back, that default is read-write: a compromised step
//      then holds a token that can push commits, move tags, or publish a release. Declaring
//      the floor once per file means a job added later cannot forget it into write access.
//
// Both checks are line-level, so this script parses no YAML and needs no dependencies. It
// runs from a bare checkout with nothing installed, which is the point: the check that guards
// the supply chain must not itself depend on the supply chain.

'use strict';

const fs = require('fs');
const path = require('path');

const workflowsDir = path.resolve(__dirname, '..', '.github', 'workflows');

// Refs that cannot be pinned to a commit SHA, each with the reason it cannot. An entry is a
// standing exception, not a waiver: the reason is printed on every run so a reader sees the
// exception and can judge it. Keys are `owner/repo`; any subpath under that repository is
// covered by the entry. Add one only when the action itself rejects a SHA.
const ALLOWLIST = {
  // The generator resolves its own ref against the release tag it was published under and
  // refuses to run when called by digest, so a SHA pin makes it fail closed rather than
  // merely unverified.
  'slsa-framework/slsa-github-generator':
    'the generator resolves its own ref against the release tag it was published under and ' +
    'refuses to run when called by digest',
};

const SHA_REF = /^[\w.-]+\/[\w.-]+(?:\/[\w.\-/]+)?@[0-9a-f]{40}$/;
const VERSION_COMMENT = /#\s*v?\d[\w.\-+]*/;
const USES_LINE = /^\s*(?:-\s+)?uses:\s*(.+)$/;
const TOP_LEVEL_PERMISSIONS = /^permissions:/m;
const DOCKER_DIGEST = /^docker:\/\/[^\s]+@sha256:[0-9a-f]{64}$/;

function refValue(rest) {
  // Strip a trailing comment and surrounding quotes to get the bare ref. A `#` inside a ref
  // is not legal in an action reference, so the first one starts the comment.
  const hash = rest.indexOf('#');
  const value = (hash === -1 ? rest : rest.slice(0, hash)).trim();
  return value.replace(/^['"]|['"]$/g, '');
}

function ownerRepo(ref) {
  const parts = ref.split('@')[0].split('/');
  return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : ref;
}

const problems = [];
const pinned = [];
const exempt = [];

let entries;
try {
  entries = fs.readdirSync(workflowsDir);
} catch (error) {
  console.error(`cannot read ${workflowsDir}: ${error.message}`);
  process.exit(2);
}

const files = entries.filter((name) => /\.ya?ml$/.test(name)).sort();
if (files.length === 0) {
  console.error(`no workflow files under ${workflowsDir}`);
  process.exit(2);
}

for (const file of files) {
  const full = path.join(workflowsDir, file);
  const text = fs.readFileSync(full, 'utf8');

  if (!TOP_LEVEL_PERMISSIONS.test(text)) {
    problems.push(
      `${file}: no top-level \`permissions:\` block, so every job inherits the repository ` +
        'default token scope, which may be read-write'
    );
  }

  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const match = USES_LINE.exec(lines[i]);
    if (!match) continue;

    const where = `${file}:${i + 1}`;
    const ref = refValue(match[1]);

    if (ref.startsWith('./') || ref.startsWith('.\\')) {
      // A path into this repository is already as pinned as the commit under review.
      exempt.push(`${where}  ${ref}  (local to this repository)`);
      continue;
    }

    if (ref.startsWith('docker://')) {
      if (DOCKER_DIGEST.test(ref)) {
        pinned.push(`${where}  ${ref}`);
      } else {
        problems.push(`${where}: container ref \`${ref}\` is not pinned to an image digest`);
      }
      continue;
    }

    const reason = ALLOWLIST[ownerRepo(ref)];
    if (reason) {
      exempt.push(`${where}  ${ref}  (allowlisted: ${reason})`);
      continue;
    }

    if (!SHA_REF.test(ref)) {
      problems.push(
        `${where}: \`${ref}\` is not pinned to a 40-character commit SHA. Resolve one with ` +
          `\`gh api repos/${ownerRepo(ref)}/commits/<tag> --jq .sha\``
      );
      continue;
    }

    if (!VERSION_COMMENT.test(match[1])) {
      problems.push(
        `${where}: \`${ref}\` is pinned but carries no trailing version comment. Without ` +
          '`# vX.Y.Z` a reader cannot tell what the SHA is, and Dependabot has no version ' +
          'to bump from'
      );
      continue;
    }

    pinned.push(`${where}  ${ref}  ${VERSION_COMMENT.exec(match[1])[0]}`);
  }
}

for (const line of pinned) console.log(`pinned   ${line}`);
for (const line of exempt) console.log(`exempt   ${line}`);

if (problems.length > 0) {
  console.error('');
  console.error(`${problems.length} workflow pinning problem(s):`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}

console.log('');
console.log(
  `${files.length} workflow file(s), ${pinned.length} pinned action reference(s), ` +
    `${exempt.length} exempt, every file declares a top-level permissions block.`
);
