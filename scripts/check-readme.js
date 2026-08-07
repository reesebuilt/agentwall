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

function leavesRepository(relativePath) {
  return relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath);
}

function cleanTarget(rawTarget) {
  let target = rawTarget.trim();
  if (target.startsWith('<') && target.endsWith('>')) target = target.slice(1, -1);
  target = target.split(/\s+["'][^"']*["']\s*$/)[0];
  return target;
}

function repositoryTarget(target) {
  const withoutFragment = target.split('#')[0].split('?')[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    return { failure: 'invalid-encoding' };
  }

  const resolved = path.resolve(path.dirname(readmePath), decoded);
  const relativeToRoot = path.relative(ROOT, resolved);
  if (leavesRepository(relativeToRoot)) return { failure: 'outside-repository' };
  return {
    resolved,
    repositoryPath: relativeToRoot.split(path.sep).join('/'),
  };
}

function addTarget(targets, rawTarget) {
  const target = cleanTarget(rawTarget);
  if (!target || target.startsWith('#') || /^https?:\/\//i.test(target)) return null;
  if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(target)) return null;
  targets.add(target);
  return target;
}

function stripIndentedCodeBlocks(markdown) {
  const output = [];
  let insideRawHtml = false;
  for (const line of markdown.split('\n')) {
    if (!insideRawHtml && /^ {0,3}<\/?[A-Za-z][A-Za-z0-9-]*(?:\s|>|\/>)/.test(line)) {
      insideRawHtml = true;
    }
    if (insideRawHtml) {
      output.push(line);
      if (line.trim() === '') insideRawHtml = false;
    } else {
      output.push(/^(?: {4}|\t)/.test(line) ? '' : line);
    }
  }
  return output.join('\n');
}

function collectTargets(markdown) {
  const targets = new Set();
  const imageTargets = new Set();
  const renderedMarkup = stripIndentedCodeBlocks(
    markdown
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/```[\s\S]*?```/g, '')
      .replace(/~~~[\s\S]*?~~~/g, '')
      .replace(/`[^`\n]*`/g, ''),
  );

  for (const match of renderedMarkup.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = addTarget(targets, match[1]);
    if (target) imageTargets.add(target);
  }

  for (const match of renderedMarkup.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    addTarget(targets, match[1]);
  }

  for (const match of renderedMarkup.matchAll(/<img\b[^>]*>/gi)) {
    const source = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(match[0]);
    if (source) {
      const target = addTarget(targets, source[1]);
      if (target) imageTargets.add(target);
    }
  }

  for (const match of renderedMarkup.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    addTarget(targets, match[1]);
  }

  for (const match of renderedMarkup.matchAll(/\bsrcset\s*=\s*["']([^"']+)["']/gi)) {
    for (const candidate of match[1].split(',')) {
      const target = addTarget(targets, candidate.trim().split(/\s+/)[0]);
      if (target) imageTargets.add(target);
    }
  }

  return { targets, imageTargets };
}

function resolveLocalTarget(target) {
  const result = repositoryTarget(target);
  if (result.failure === 'invalid-encoding') {
    fail(`${target}: invalid URL encoding`);
    return;
  }
  if (result.failure === 'outside-repository') {
    fail(`${target}: target leaves the repository`);
    return;
  }
  if (!fs.existsSync(result.resolved)) fail(`${target}: local target does not exist`);
}

const readmeRelativeToRoot = path.relative(ROOT, readmePath);
if (leavesRepository(readmeRelativeToRoot)) {
  fail(`${readmeArgument}: README path leaves the repository`);
} else if (!fs.existsSync(readmePath)) {
  fail(`${readmeArgument}: README file does not exist`);
}

const markdown = failures.length === 0 ? fs.readFileSync(readmePath, 'utf8') : '';
const { targets, imageTargets } = collectTargets(markdown);
for (const target of targets) resolveLocalTarget(target);
const normalizedImageTargets = new Set(
  [...imageTargets]
    .map((target) => repositoryTarget(target))
    .filter((target) => !target.failure)
    .map((target) => target.repositoryPath),
);

const pictureBlocks = [...markdown.matchAll(/<picture\b[^>]*>([\s\S]*?)<\/picture>/gi)].map((match) => match[0]);
const primaryLogo = 'assets/brand/agentwall-logo-primary.svg';
const reverseLogo = 'assets/brand/agentwall-logo-reverse.svg';
const themeAwareLogo = pictureBlocks.some((picture) => {
  const sourceElements = [...picture.matchAll(/<source\b[^>]*>/gi)].map((match) => match[0]);
  const hasDarkReverseSource = sourceElements.some((source) => {
    const hasDarkMedia = /\bmedia\s*=\s*["'][^"']*prefers-color-scheme\s*:\s*dark[^"']*["']/i.test(source);
    const hasReverseSource = new RegExp(`\\bsrcset\\s*=\\s*["']${reverseLogo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\s+[^"']+)?["']`, 'i').test(source);
    return hasDarkMedia && hasReverseSource;
  });
  const hasPrimaryImage = new RegExp(`<img\\b[^>]*\\bsrc\\s*=\\s*["']${primaryLogo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`, 'i').test(picture);
  return hasDarkReverseSource && hasPrimaryImage;
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
      } else {
        const manifestImage = path.posix.normalize(image.file.replaceAll('\\', '/'));
        if (!normalizedImageTargets.has(manifestImage)) {
          fail(`${image.file}: README does not reference this manifest image`);
        }
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
