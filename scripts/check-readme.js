#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const readmeArgument = process.argv[2] || 'README.md';
const readmePath = path.resolve(ROOT, readmeArgument);
const manifestPath = path.join(ROOT, 'docs/assets/agentwall-readme-visuals.json');
const failures = [];

function fail(message) {
  failures.push(message);
}

function cleanTarget(rawTarget) {
  let target = rawTarget.trim();
  if (target.startsWith('<') && target.endsWith('>')) target = target.slice(1, -1);
  target = target.split(/\s+["'][^"']*["']\s*$/)[0];
  return target;
}

function addTarget(targets, rawTarget) {
  const target = cleanTarget(rawTarget);
  if (!target || target.startsWith('#') || /^https?:\/\//i.test(target)) return;
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(target)) return;
  targets.add(target);
}

function collectTargets(markdown) {
  const targets = new Set();

  for (const match of markdown.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    addTarget(targets, match[1]);
  }

  for (const match of markdown.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    addTarget(targets, match[1]);
  }

  for (const match of markdown.matchAll(/\bsrcset\s*=\s*["']([^"']+)["']/gi)) {
    for (const candidate of match[1].split(',')) {
      addTarget(targets, candidate.trim().split(/\s+/)[0]);
    }
  }

  return targets;
}

function resolveLocalTarget(target) {
  const withoutFragment = target.split('#')[0].split('?')[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    fail(`${target}: invalid URL encoding`);
    return;
  }

  const resolved = path.resolve(path.dirname(readmePath), decoded);
  const relativeToRoot = path.relative(ROOT, resolved);
  if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
    fail(`${target}: target leaves the repository`);
    return;
  }
  if (!fs.existsSync(resolved)) fail(`${target}: local target does not exist`);
}

if (!fs.existsSync(readmePath)) {
  fail(`${readmeArgument}: README file does not exist`);
}

const markdown = failures.length === 0 ? fs.readFileSync(readmePath, 'utf8') : '';
const targets = collectTargets(markdown);
for (const target of targets) resolveLocalTarget(target);

const pictureBlocks = [...markdown.matchAll(/<picture\b[^>]*>([\s\S]*?)<\/picture>/gi)].map((match) => match[0]);
const primaryLogo = 'assets/brand/agentwall-logo-primary.svg';
const reverseLogo = 'assets/brand/agentwall-logo-reverse.svg';
const themeAwareLogo = pictureBlocks.some((picture) => {
  const hasDarkMedia = /<source\b[^>]*media\s*=\s*["'][^"']*prefers-color-scheme\s*:\s*dark[^"']*["'][^>]*>/i.test(picture);
  const hasReverseSource = new RegExp(`\\bsrcset\\s*=\\s*["']${reverseLogo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\s+[^"']+)?["']`, 'i').test(picture);
  const hasPrimaryImage = new RegExp(`<img\\b[^>]*\\bsrc\\s*=\\s*["']${primaryLogo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`, 'i').test(picture);
  return hasDarkMedia && hasReverseSource && hasPrimaryImage;
});
if (!themeAwareLogo) {
  fail(`README requires one theme-aware <picture> with ${reverseLogo} for dark mode and ${primaryLogo} for light mode`);
}

if (!fs.existsSync(manifestPath)) {
  fail('docs/assets/agentwall-readme-visuals.json: screenshot manifest does not exist');
} else {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    fail(`docs/assets/agentwall-readme-visuals.json: ${error.message}`);
  }
  if (Array.isArray(manifest)) {
    for (const image of manifest) {
      if (!image || typeof image.file !== 'string') {
        fail('docs/assets/agentwall-readme-visuals.json: every image requires a file path');
      } else if (!markdown.includes(image.file)) {
        fail(`${image.file}: README does not reference this manifest image`);
      }
    }
  } else if (manifest !== undefined) {
    fail('docs/assets/agentwall-readme-visuals.json: manifest must be an array');
  }
}

if (failures.length > 0) {
  console.error('README contract check failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`README contract check passed (${targets.size} local and external targets inspected).`);
