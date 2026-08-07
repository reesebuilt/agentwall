#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const PALETTE = new Set(['#0F131B', '#F1F5FA', '#5FE6C8', '#313B49', '#A7B4C5']);
const WORDMARK_VIEWBOX = '0 0 960 256';
const MARK_VIEWBOX = '0 0 512 512';
const SOCIAL_VIEWBOX = '0 0 1280 640';
const PNG_LIMIT = 1_048_576;

const SVG_ASSETS = [
  { file: 'assets/brand/agentwall-logo-primary.svg', kind: 'wordmark', outlined: true },
  { file: 'assets/brand/agentwall-logo-reverse.svg', kind: 'wordmark', outlined: true },
  { file: 'assets/brand/agentwall-logo-mark.svg', kind: 'mark' },
  { file: 'assets/brand/agentwall-logo-monochrome.svg', kind: 'wordmark' },
  { file: 'public/assets/brand/agentwall-logo-primary.svg', kind: 'wordmark', outlined: true, publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-reverse.svg', kind: 'wordmark', outlined: true, publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-mark.svg', kind: 'mark', publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-monochrome.svg', kind: 'wordmark', publicMark: true },
  { file: 'public/assets/brand/favicon.svg', kind: 'mark', publicMark: true },
  { file: 'public/assets/brand/agentwall-social-card.svg', kind: 'social', publicMark: true },
];

const PNG_ASSET = 'docs/assets/agentwall-social-preview.png';
const FORBIDDEN_ELEMENTS = new Set([
  'text',
  'lineargradient',
  'radialgradient',
  'filter',
  'mask',
  'script',
  'image',
  'foreignobject',
]);
const COLOR_ATTRIBUTES = new Set([
  'color',
  'fill',
  'flood-color',
  'lighting-color',
  'stop-color',
  'stroke',
]);
const GEOMETRY_ATTRIBUTES = ['d', 'x', 'y', 'width', 'height', 'rx', 'ry'];

const failures = [];
const parsedAssets = new Map();

function fail(message) {
  failures.push(message);
}

function parseXml(source) {
  const document = { name: '#document', attrs: {}, children: [], text: '' };
  const stack = [document];
  let cursor = source.charCodeAt(0) === 0xfeff ? 1 : 0;

  function appendText(text) {
    if (stack.length === 1 && text.trim()) throw new Error('text appears outside the root element');
    stack[stack.length - 1].text += text;
  }

  function findTagEnd(start) {
    let quote = null;
    for (let index = start; index < source.length; index += 1) {
      const character = source[index];
      if (quote) {
        if (character === quote) quote = null;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === '>') {
        return index;
      }
    }
    return -1;
  }

  function parseAttributes(fragment) {
    const attrs = {};
    let index = 0;
    while (index < fragment.length) {
      while (/\s/.test(fragment[index] || '')) index += 1;
      if (index >= fragment.length) break;

      const nameMatch = /^[A-Za-z_:][A-Za-z0-9_.:-]*/.exec(fragment.slice(index));
      if (!nameMatch) throw new Error(`invalid attribute near ${JSON.stringify(fragment.slice(index, index + 24))}`);
      const name = nameMatch[0];
      index += name.length;
      while (/\s/.test(fragment[index] || '')) index += 1;
      if (fragment[index] !== '=') throw new Error(`attribute ${name} has no value`);
      index += 1;
      while (/\s/.test(fragment[index] || '')) index += 1;
      const quote = fragment[index];
      if (quote !== '"' && quote !== "'") throw new Error(`attribute ${name} is not quoted`);
      index += 1;
      const end = fragment.indexOf(quote, index);
      if (end === -1) throw new Error(`attribute ${name} has an unterminated value`);
      if (Object.hasOwn(attrs, name)) throw new Error(`attribute ${name} appears more than once`);
      attrs[name] = fragment.slice(index, end);
      index = end + 1;
    }
    return attrs;
  }

  while (cursor < source.length) {
    const open = source.indexOf('<', cursor);
    if (open === -1) {
      appendText(source.slice(cursor));
      cursor = source.length;
      break;
    }
    appendText(source.slice(cursor, open));

    if (source.startsWith('<!--', open)) {
      const end = source.indexOf('-->', open + 4);
      if (end === -1) throw new Error('unterminated XML comment');
      cursor = end + 3;
      continue;
    }
    if (source.startsWith('<?', open)) {
      const end = source.indexOf('?>', open + 2);
      if (end === -1) throw new Error('unterminated processing instruction');
      cursor = end + 2;
      continue;
    }
    if (source.startsWith('<![CDATA[', open)) {
      const end = source.indexOf(']]>', open + 9);
      if (end === -1) throw new Error('unterminated CDATA section');
      appendText(source.slice(open + 9, end));
      cursor = end + 3;
      continue;
    }
    if (source.startsWith('<!', open)) throw new Error('DTD and XML declarations are not permitted');

    const close = findTagEnd(open + 1);
    if (close === -1) throw new Error('unterminated XML tag');
    const rawTag = source.slice(open + 1, close).trim();
    if (!rawTag) throw new Error('empty XML tag');

    if (rawTag.startsWith('/')) {
      const name = rawTag.slice(1).trim();
      if (!/^[A-Za-z_:][A-Za-z0-9_.:-]*$/.test(name)) throw new Error(`invalid closing tag ${name}`);
      const current = stack.pop();
      if (stack.length === 0 || current.name !== name) {
        throw new Error(`closing tag ${name} does not match ${current ? current.name : 'nothing'}`);
      }
      cursor = close + 1;
      continue;
    }

    const selfClosing = rawTag.endsWith('/');
    const startTag = selfClosing ? rawTag.slice(0, -1).trimEnd() : rawTag;
    const nameMatch = /^[A-Za-z_:][A-Za-z0-9_.:-]*/.exec(startTag);
    if (!nameMatch) throw new Error(`invalid opening tag ${rawTag}`);
    const name = nameMatch[0];
    const node = {
      name,
      attrs: parseAttributes(startTag.slice(name.length)),
      children: [],
      text: '',
    };
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) stack.push(node);
    cursor = close + 1;
  }

  if (stack.length !== 1) throw new Error(`unclosed element ${stack[stack.length - 1].name}`);
  if (document.children.length !== 1) throw new Error('document must contain exactly one root element');
  if (document.children[0].name !== 'svg') throw new Error('root element must be svg');
  return document.children[0];
}

function allElements(root) {
  const elements = [];
  const visit = (node) => {
    elements.push(node);
    for (const child of node.children) visit(child);
  };
  visit(root);
  return elements;
}

function textContent(node) {
  return `${node.text}${node.children.map(textContent).join('')}`;
}

function normalizeViewBox(value) {
  return String(value || '').trim().split(/[\s,]+/).join(' ');
}

function validateAccessibility(root, elements, file) {
  const titles = elements.filter((element) => element.name.toLowerCase() === 'title');
  const descriptions = elements.filter((element) => element.name.toLowerCase() === 'desc');
  if (titles.length !== 1 || !textContent(titles[0] || { text: '', children: [] }).trim()) {
    fail(`${file}: requires exactly one non-empty title`);
  }
  if (descriptions.length !== 1 || !textContent(descriptions[0] || { text: '', children: [] }).trim()) {
    fail(`${file}: requires exactly one non-empty desc`);
  }
  if (root.attrs.role !== 'img') fail(`${file}: root svg must use role="img"`);

  const labelledBy = String(root.attrs['aria-labelledby'] || '').trim().split(/\s+/).filter(Boolean);
  const titleId = titles[0] && titles[0].attrs.id;
  const descId = descriptions[0] && descriptions[0].attrs.id;
  if (!titleId || !descId || labelledBy.length !== 2 || labelledBy[0] !== titleId || labelledBy[1] !== descId) {
    fail(`${file}: aria-labelledby must reference the title and desc in that order`);
  }
}

function validateSafeSvg(source, elements, file) {
  for (const element of elements) {
    const elementName = element.name.toLowerCase();
    if (FORBIDDEN_ELEMENTS.has(elementName)) fail(`${file}: forbidden <${element.name}> element`);
    if (Object.hasOwn(element.attrs, 'style')) fail(`${file}: style attributes are not permitted`);

    for (const [name, value] of Object.entries(element.attrs)) {
      const lowerName = name.toLowerCase();
      if (lowerName === 'xmlns') continue;
      if (/^(?:https?:)?\/\//i.test(value) || /data:/i.test(value)) {
        fail(`${file}: external URLs and embedded data are not permitted (${name})`);
      }
      if (/url\((?!\s*#[^)]+\s*\))/i.test(value)) fail(`${file}: external url() reference in ${name}`);
      if ((lowerName === 'href' || lowerName === 'xlink:href') && !value.startsWith('#')) {
        fail(`${file}: external ${name} is not permitted`);
      }
      if (COLOR_ATTRIBUTES.has(lowerName) && value !== 'none' && !PALETTE.has(value)) {
        fail(`${file}: undeclared color ${value} in ${name}`);
      }
    }
  }

  const declaredHexColors = source.match(/#[0-9A-Fa-f]{3,8}\b/g) || [];
  for (const color of declaredHexColors) {
    if (!PALETTE.has(color)) fail(`${file}: undeclared or non-canonical color ${color}`);
  }
}

function validateGeometry(root, elements, asset) {
  const expectedViewBox = asset.kind === 'wordmark'
    ? WORDMARK_VIEWBOX
    : asset.kind === 'mark'
      ? MARK_VIEWBOX
      : SOCIAL_VIEWBOX;
  if (normalizeViewBox(root.attrs.viewBox) !== expectedViewBox) {
    fail(`${asset.file}: expected viewBox="${expectedViewBox}"`);
  }
  if (asset.kind === 'social' && (root.attrs.width !== '1280' || root.attrs.height !== '640')) {
    fail(`${asset.file}: social SVG must declare width="1280" height="640"`);
  }
  if (asset.outlined) {
    const wordmarkPaths = elements.filter(
      (element) => element.name === 'path' && element.attrs['data-part'] === 'wordmark' && element.attrs.d,
    );
    if (wordmarkPaths.length !== 1) fail(`${asset.file}: outlined wordmark path is missing or duplicated`);
  }
}

function markGeometry(elements) {
  return elements
    .filter((element) => element.attrs['data-mark-part'])
    .sort((left, right) => left.attrs['data-mark-part'].localeCompare(right.attrs['data-mark-part']))
    .map((element) => ({
      part: element.attrs['data-mark-part'],
      element: element.name,
      geometry: Object.fromEntries(
        GEOMETRY_ATTRIBUTES.filter((name) => Object.hasOwn(element.attrs, name)).map((name) => [name, element.attrs[name]]),
      ),
    }));
}

function validateMarkCopies() {
  const canonical = parsedAssets.get('assets/brand/agentwall-logo-mark.svg');
  if (!canonical) return;
  const expected = JSON.stringify(markGeometry(canonical.elements));
  for (const asset of SVG_ASSETS.filter((candidate) => candidate.publicMark)) {
    const parsed = parsedAssets.get(asset.file);
    if (!parsed) continue;
    const actualGeometry = markGeometry(parsed.elements);
    if (actualGeometry.length !== 3 || JSON.stringify(actualGeometry) !== expected) {
      fail(`${asset.file}: public mark geometry differs from the canonical mark`);
    }
  }
}

function channelToLinear(channel) {
  const value = channel / 255;
  return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function luminance(hex) {
  const channels = [hex.slice(1, 3), hex.slice(3, 5), hex.slice(5, 7)].map((value) => Number.parseInt(value, 16));
  return 0.2126 * channelToLinear(channels[0])
    + 0.7152 * channelToLinear(channels[1])
    + 0.0722 * channelToLinear(channels[2]);
}

function contrastRatio(foreground, background) {
  const lighter = Math.max(luminance(foreground), luminance(background));
  const darker = Math.min(luminance(foreground), luminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

function validateContrast() {
  const checks = [
    { label: 'cool white normal text on graphite', foreground: '#F1F5FA', background: '#0F131B', minimum: 4.5 },
    { label: 'secondary normal text on graphite', foreground: '#A7B4C5', background: '#0F131B', minimum: 4.5 },
    { label: 'graphite normal text on cool white', foreground: '#0F131B', background: '#F1F5FA', minimum: 4.5 },
    { label: 'mint large text on graphite', foreground: '#5FE6C8', background: '#0F131B', minimum: 3 },
  ];
  for (const check of checks) {
    const ratio = contrastRatio(check.foreground, check.background);
    if (ratio < check.minimum) fail(`contrast: ${check.label} is ${ratio.toFixed(2)}:1; requires ${check.minimum}:1`);
    else console.log(`ok: contrast ${check.label} ${ratio.toFixed(2)}:1`);
  }
}

function validatePng() {
  const absolute = path.join(ROOT, PNG_ASSET);
  if (!fs.existsSync(absolute)) {
    fail(`${PNG_ASSET}: missing required social-preview PNG`);
    return;
  }
  const buffer = fs.readFileSync(absolute);
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buffer.length < 24 || !buffer.subarray(0, 8).equals(signature) || buffer.toString('ascii', 12, 16) !== 'IHDR') {
    fail(`${PNG_ASSET}: invalid PNG signature or IHDR`);
    return;
  }
  const width = buffer.readUInt32BE(16);
  const height = buffer.readUInt32BE(20);
  if (width !== 1280 || height !== 640) fail(`${PNG_ASSET}: expected 1280x640, found ${width}x${height}`);
  if (buffer.length >= PNG_LIMIT) fail(`${PNG_ASSET}: ${buffer.length} bytes exceeds the ${PNG_LIMIT - 1} byte maximum`);
  if (width === 1280 && height === 640 && buffer.length < PNG_LIMIT) {
    console.log(`ok: ${PNG_ASSET} (1280x640, ${buffer.length} bytes)`);
  }
}

for (const asset of SVG_ASSETS) {
  const absolute = path.join(ROOT, asset.file);
  if (!fs.existsSync(absolute)) {
    fail(`${asset.file}: missing required SVG`);
    continue;
  }
  try {
    const source = fs.readFileSync(absolute, 'utf8');
    const root = parseXml(source);
    const elements = allElements(root);
    parsedAssets.set(asset.file, { source, root, elements });
    validateAccessibility(root, elements, asset.file);
    validateSafeSvg(source, elements, asset.file);
    validateGeometry(root, elements, asset);
    console.log(`ok: ${asset.file} (XML parsed)`);
  } catch (error) {
    fail(`${asset.file}: XML parse failed: ${error.message}`);
  }
}

validateMarkCopies();
validatePng();
validateContrast();

if (failures.length) {
  console.error(`\nBrand asset check failed with ${failures.length} issue${failures.length === 1 ? '' : 's'}:`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`\nBrand asset check passed: ${SVG_ASSETS.length} SVGs, 1 PNG, canonical palette, and WCAG contrast.`);
}
