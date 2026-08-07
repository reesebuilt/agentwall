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

function addSourceSetTargets(sourceSet, targets, imageTargets) {
  for (const candidate of sourceSet.split(',')) {
    const target = addTarget(targets, candidate.trim().split(/\s+/)[0]);
    if (target && imageTargets) imageTargets.add(target);
  }
}

function collectHtmlTargets(html, targets, imageTargets, parseFragment) {
  const fragment = parseFragment(html);

  function visit(node) {
    if (node.tagName && Array.isArray(node.attrs)) {
      const attributes = new Map(node.attrs.map((attribute) => [attribute.name, attribute.value]));
      const source = attributes.get('src');
      const sourceSet = attributes.get('srcset');

      if (node.tagName === 'img' && source !== undefined) {
        const target = addTarget(targets, source);
        if (target) imageTargets.add(target);
      }
      if ((node.tagName === 'img' || node.tagName === 'source') && sourceSet !== undefined) {
        addSourceSetTargets(sourceSet, targets, imageTargets);
      }

      const href = attributes.get('href');
      if (href !== undefined) addTarget(targets, href);
      if (source !== undefined) addTarget(targets, source);
      if (sourceSet !== undefined) addSourceSetTargets(sourceSet, targets, null);
    }

    for (const child of node.childNodes || []) visit(child);
    if (node.content) visit(node.content);
  }

  visit(fragment);
}

function collectTargets(markdown, lexer, walkTokens, parseFragment) {
  const targets = new Set();
  const imageTargets = new Set();
  const htmlFragments = [];
  const tokens = lexer(markdown, { gfm: true });

  walkTokens(tokens, (token) => {
    if (token.type === 'image') {
      const target = addTarget(targets, token.href);
      if (target) imageTargets.add(target);
    } else if (token.type === 'link') {
      addTarget(targets, token.href);
    } else if (token.type === 'html') {
      const renderedHtml = token.raw.replace(/<!--[\s\S]*?-->/g, '');
      htmlFragments.push(renderedHtml);
      collectHtmlTargets(renderedHtml, targets, imageTargets, parseFragment);
    }
  });

  return {
    targets,
    imageTargets,
    htmlMarkup: htmlFragments.join('\n'),
  };
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

async function main() {
  const readmeRelativeToRoot = path.relative(ROOT, readmePath);
  if (leavesRepository(readmeRelativeToRoot)) {
    fail(`${readmeArgument}: README path leaves the repository`);
  } else if (!fs.existsSync(readmePath)) {
    fail(`${readmeArgument}: README file does not exist`);
  }

  const markdown = failures.length === 0 ? fs.readFileSync(readmePath, 'utf8') : '';
  const [{ lexer, walkTokens }, { parseFragment }] = await Promise.all([import('marked'), import('parse5')]);
  const { targets, imageTargets, htmlMarkup } = collectTargets(markdown, lexer, walkTokens, parseFragment);
  for (const target of targets) resolveLocalTarget(target);
  const normalizedImageTargets = new Set(
    [...imageTargets]
      .map((target) => repositoryTarget(target))
      .filter((target) => !target.failure)
      .map((target) => target.repositoryPath),
  );

  const pictureBlocks = [...htmlMarkup.matchAll(/<picture\b[^>]*>([\s\S]*?)<\/picture>/gi)].map((match) => match[0]);
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
    process.exitCode = 1;
    return;
  }

  console.log(`README contract check passed (${targets.size} repository-relative targets inspected).`);
}

main().catch((error) => {
  console.error('README contract check failed:');
  console.error(`- Markdown parser error: ${error.message}`);
  process.exitCode = 1;
});
