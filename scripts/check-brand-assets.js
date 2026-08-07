#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const ROOT = path.resolve(__dirname, '..');
const PALETTE = new Set(['#0F131B', '#F1F5FA', '#5FE6C8', '#313B49', '#A7B4C5']);
const WORDMARK_VIEWBOX = '0 0 960 256';
const MARK_VIEWBOX = '0 0 512 512';
const SOCIAL_VIEWBOX = '0 0 1280 640';
const PNG_LIMIT = 1_048_576;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const MARK_FIELD = Object.freeze({
  element: 'rect',
  x: '32',
  y: '32',
  width: '448',
  height: '448',
  rx: '104',
  fill: '#0F131B',
});
const MARK_FRAME_D = 'M176 112H336L400 176V336L336 400H176L112 336V176L176 112ZM208 176L176 208V304L208 336H304L336 304V208L304 176H208Z';
const MARK_ACTION = Object.freeze({
  element: 'rect',
  x: '228',
  y: '228',
  width: '56',
  height: '56',
  fill: '#5FE6C8',
});
const MONOCHROME_MARK_D = `M136 32H376A104 104 0 0 1 480 136V376A104 104 0 0 1 376 480H136A104 104 0 0 1 32 376V136A104 104 0 0 1 136 32Z${MARK_FRAME_D}M228 228H284V284H228Z`;
const WORDMARK_PATH_SHA256 = '829c3052ef6b5d5c972c7852eb8caaac08b405132cf3bf3368e133fb231ebba5';
const STATEMENT_PATH_SHA256 = '0c44864a29a737e39025e111b32390dcb69a5f6a50fc08f9f6157f96cbe51d5e';

const SVG_ASSETS = [
  { file: 'assets/brand/agentwall-logo-primary.svg', kind: 'wordmark', variant: 'primary' },
  { file: 'assets/brand/agentwall-logo-reverse.svg', kind: 'wordmark', variant: 'reverse' },
  { file: 'assets/brand/agentwall-logo-mark.svg', kind: 'mark', variant: 'mark' },
  { file: 'assets/brand/agentwall-logo-monochrome.svg', kind: 'wordmark', variant: 'monochrome' },
  { file: 'public/assets/brand/agentwall-logo-primary.svg', kind: 'wordmark', variant: 'primary', publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-reverse.svg', kind: 'wordmark', variant: 'reverse', publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-mark.svg', kind: 'mark', variant: 'mark', publicMark: true },
  { file: 'public/assets/brand/agentwall-logo-monochrome.svg', kind: 'wordmark', variant: 'monochrome', publicMark: true },
  { file: 'public/assets/brand/favicon.svg', kind: 'mark', variant: 'mark', publicMark: true },
  { file: 'public/assets/brand/agentwall-social-card.svg', kind: 'social', variant: 'social', publicMark: true },
];

const PNG_ASSET = 'docs/assets/agentwall-social-preview.png';
const ELEMENT_ATTRIBUTES = new Map([
  ['svg', new Set(['width', 'height', 'viewBox', 'fill', 'xmlns', 'role', 'aria-labelledby'])],
  ['title', new Set(['id'])],
  ['desc', new Set(['id'])],
  ['g', new Set(['data-part', 'transform'])],
  ['rect', new Set(['data-mark-part', 'x', 'y', 'width', 'height', 'rx', 'fill'])],
  ['path', new Set(['data-mark-part', 'data-part', 'fill', 'fill-rule', 'clip-rule', 'd', 'transform'])],
]);
const COLOR_ATTRIBUTES = new Set(['fill']);
const EXPECTED_TRANSFORMS = Object.freeze({
  primary: [
    'g:mark:scale(0.5)',
    'path:wordmark:translate(292 155) scale(0.1 -0.1)',
  ],
  reverse: [
    'g:mark:scale(0.5)',
    'path:wordmark:translate(252 155) scale(0.1 -0.1)',
  ],
  mark: [],
  monochrome: [
    'g:mark:scale(0.5)',
    'path:wordmark:translate(292 155) scale(0.1 -0.1)',
  ],
  social: [
    'g:mark:translate(144 80) scale(0.375)',
    'path:statement:translate(121 496) scale(0.038 -0.038)',
    'path:wordmark:translate(366 216) scale(0.14 -0.14)',
  ],
});

const failures = [];

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
      const instruction = source.slice(open + 2, end).trim();
      if (/(?:href|src|url|https?:|@import|stylesheet)/i.test(instruction)) {
        throw new Error('URL-bearing processing instructions and external CSS are not permitted');
      }
      throw new Error('processing instructions are not permitted');
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
  if (/(?:<\?xml-stylesheet|@import\s|javascript:|data:image\/|url\s*\()/i.test(source)) {
    fail(`${file}: external CSS, scripts, URL references, and embedded raster data are not permitted`);
  }

  for (const element of elements) {
    const allowedAttributes = ELEMENT_ATTRIBUTES.get(element.name);
    if (!allowedAttributes) {
      fail(`${file}: element <${element.name}> is not permitted`);
      continue;
    }
    if (!['title', 'desc'].includes(element.name) && element.text.trim()) {
      fail(`${file}: text content is only permitted inside title and desc`);
    }

    for (const [name, value] of Object.entries(element.attrs)) {
      const lowerName = name.toLowerCase();
      if (lowerName.startsWith('on')) fail(`${file}: event attribute ${name} is not permitted`);
      if (!allowedAttributes.has(name)) fail(`${file}: attribute ${name} is not permitted on <${element.name}>`);
      if (name === 'xmlns') {
        if (value !== 'http://www.w3.org/2000/svg') fail(`${file}: unexpected SVG namespace ${value}`);
        continue;
      }
      if (/(?:https?:|(?:^|:)\/\/|data:|javascript:|url\s*\(|@import)/i.test(value)) {
        fail(`${file}: URL-bearing attribute ${name} is not permitted`);
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

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function findPart(elements, attribute, value, file) {
  const matches = elements.filter((element) => element.attrs[attribute] === value);
  if (matches.length !== 1) {
    fail(`${file}: requires exactly one ${attribute}="${value}" element`);
    return null;
  }
  return matches[0];
}

function expectGeometry(element, expected, file, label) {
  if (!element) return;
  if (element.name !== expected.element) fail(`${file}: ${label} must use <${expected.element}>`);
  for (const [attribute, value] of Object.entries(expected)) {
    if (attribute === 'element') continue;
    if (element.attrs[attribute] !== value) {
      fail(`${file}: ${label} requires ${attribute}="${value}"`);
    }
  }
  for (const attribute of ['x', 'y', 'width', 'height', 'rx', 'd']) {
    if (!Object.hasOwn(expected, attribute) && Object.hasOwn(element.attrs, attribute)) {
      fail(`${file}: ${label} has unexpected geometry attribute ${attribute}`);
    }
  }
}

function validateTransforms(elements, asset) {
  const actual = elements
    .filter((element) => Object.hasOwn(element.attrs, 'transform'))
    .map((element) => `${element.name}:${element.attrs['data-part'] || ''}:${element.attrs.transform}`)
    .sort();
  const expected = [...EXPECTED_TRANSFORMS[asset.variant]].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${asset.file}: transforms differ from the permitted ${asset.variant} transforms`);
  }
}

function validateMarkGeometry(elements, asset) {
  if (asset.variant === 'monochrome') {
    const mark = findPart(elements, 'data-mark-part', 'monochrome-knockout', asset.file);
    if (mark && mark.attrs.d !== MONOCHROME_MARK_D) {
      fail(`${asset.file}: monochrome knockout mark differs from the canonical field, octagon, or action geometry`);
    }
    if (mark && (mark.attrs.fill !== '#0F131B' || mark.attrs['fill-rule'] !== 'evenodd' || mark.attrs['clip-rule'] !== 'evenodd')) {
      fail(`${asset.file}: monochrome mark must use one graphite fill with transparent even-odd knockouts`);
    }
    const markParts = elements.filter((element) => element.attrs['data-mark-part']);
    if (markParts.length !== 1) fail(`${asset.file}: monochrome mark geometry is duplicated`);
    return;
  }

  const field = findPart(elements, 'data-mark-part', 'field', asset.file);
  const frame = findPart(elements, 'data-mark-part', 'frame', asset.file);
  const action = findPart(elements, 'data-mark-part', 'action', asset.file);
  expectGeometry(field, MARK_FIELD, asset.file, 'mark field');
  expectGeometry(action, MARK_ACTION, asset.file, 'protected action');
  if (frame && (
    frame.name !== 'path'
    || frame.attrs.d !== MARK_FRAME_D
    || frame.attrs.fill !== '#5FE6C8'
    || frame.attrs['fill-rule'] !== 'evenodd'
    || frame.attrs['clip-rule'] !== 'evenodd'
  )) {
    fail(`${asset.file}: control frame differs from the canonical mint octagon`);
  }
  const markParts = elements.filter((element) => element.attrs['data-mark-part']);
  if (markParts.length !== 3) fail(`${asset.file}: mark must contain exactly the canonical field, frame, and action`);
}
function validateShapeInventory(elements, asset) {
  const actual = elements
    .filter((element) => element.name === 'rect' || element.name === 'path')
    .map((element) => {
      const part = element.attrs['data-mark-part']
        || element.attrs['data-part']
        || (element.name === 'rect' ? 'background' : '');
      return `${element.name}:${part}`;
    })
    .sort();
  const standardMark = ['path:frame', 'rect:action', 'rect:field'];
  const expectedByVariant = {
    primary: [...standardMark, 'path:wordmark'],
    reverse: [...standardMark, 'path:wordmark'],
    mark: standardMark,
    monochrome: ['path:monochrome-knockout', 'path:wordmark'],
    social: [...standardMark, 'path:statement', 'path:wordmark', 'rect:background'],
  };
  const expected = [...expectedByVariant[asset.variant]].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${asset.file}: drawing element inventory differs from the canonical ${asset.variant} asset`);
  }
}


function validateGeometry(root, elements, asset) {
  const expectedViewBox = asset.kind === 'wordmark'
    ? WORDMARK_VIEWBOX
    : asset.kind === 'mark'
      ? MARK_VIEWBOX
      : SOCIAL_VIEWBOX;
  const [expectedWidth, expectedHeight] = expectedViewBox.split(' ').slice(2);
  if (
    normalizeViewBox(root.attrs.viewBox) !== expectedViewBox
    || root.attrs.width !== expectedWidth
    || root.attrs.height !== expectedHeight
  ) {
    fail(`${asset.file}: expected width="${expectedWidth}" height="${expectedHeight}" viewBox="${expectedViewBox}"`);
  }
  if (root.attrs.fill !== 'none') fail(`${asset.file}: root svg must use fill="none"`);
  validateShapeInventory(elements, asset);

  validateTransforms(elements, asset);
  validateMarkGeometry(elements, asset);

  if (asset.kind === 'wordmark' || asset.kind === 'social') {
    const wordmark = findPart(elements, 'data-part', 'wordmark', asset.file);
    if (!wordmark || wordmark.name !== 'path' || sha256(wordmark.attrs.d || '') !== WORDMARK_PATH_SHA256) {
      fail(`${asset.file}: outlined wordmark geometry differs from the canonical Montserrat path`);
    }
    const expectedFill = asset.variant === 'primary' || asset.variant === 'monochrome' ? '#0F131B' : '#F1F5FA';
    if (wordmark && wordmark.attrs.fill !== expectedFill) {
      fail(`${asset.file}: wordmark requires fill="${expectedFill}"`);
    }
  }

  if (asset.variant === 'social') {
    const statement = findPart(elements, 'data-part', 'statement', asset.file);
    if (!statement || statement.name !== 'path' || sha256(statement.attrs.d || '') !== STATEMENT_PATH_SHA256) {
      fail(`${asset.file}: product statement outline differs from the canonical path`);
    }
    if (statement && statement.attrs.fill !== '#A7B4C5') {
      fail(`${asset.file}: product statement requires fill="#A7B4C5"`);
    }
    const backgrounds = elements.filter(
      (element) => element.name === 'rect' && !element.attrs['data-mark-part'],
    );
    if (
      backgrounds.length !== 1
      || backgrounds[0].attrs.width !== '1280'
      || backgrounds[0].attrs.height !== '640'
      || backgrounds[0].attrs.fill !== '#0F131B'
    ) {
      fail(`${asset.file}: social card requires one solid 1280 by 640 graphite background`);
    }
  }

  if (asset.variant === 'monochrome') {
    const fills = new Set(
      elements.map((element) => element.attrs.fill).filter((fill) => fill && fill !== 'none'),
    );
    if (fills.size !== 1 || !fills.has('#0F131B')) {
      fail(`${asset.file}: monochrome logo must use one graphite ink`);
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

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function paeth(left, above, upperLeft) {
  const estimate = left + above - upperLeft;
  const leftDistance = Math.abs(estimate - left);
  const aboveDistance = Math.abs(estimate - above);
  const upperLeftDistance = Math.abs(estimate - upperLeft);
  if (leftDistance <= aboveDistance && leftDistance <= upperLeftDistance) return left;
  if (aboveDistance <= upperLeftDistance) return above;
  return upperLeft;
}

function readSample(row, sampleIndex, bitDepth) {
  if (bitDepth === 8) return row[sampleIndex];
  if (bitDepth === 16) return row.readUInt16BE(sampleIndex * 2);
  const bitOffset = sampleIndex * bitDepth;
  const shift = 8 - bitDepth - (bitOffset % 8);
  return (row[Math.floor(bitOffset / 8)] >>> shift) & ((1 << bitDepth) - 1);
}

function scaleSample(sample, bitDepth) {
  if (bitDepth === 8) return sample;
  if (bitDepth === 16) return Math.round(sample / 257);
  return Math.round((sample * 255) / ((1 << bitDepth) - 1));
}

function decodePng(buffer) {
  if (buffer.length < PNG_SIGNATURE.length || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    throw new Error('invalid PNG signature');
  }

  const allowedChunks = new Set([
    'IHDR',
    'PLTE',
    'tRNS',
    'cHRM',
    'gAMA',
    'sRGB',
    'pHYs',
    'bKGD',
    'tEXt',
    'tIME',
    'IDAT',
    'IEND',
  ]);
  const idatParts = [];
  let ihdr = null;
  let palette = null;
  let transparency = null;
  let offset = 8;
  let chunkIndex = 0;
  let seenIdat = false;
  let idatEnded = false;
  let seenIend = false;
  const seenSingletonChunks = new Set();

  while (offset < buffer.length) {
    if (buffer.length - offset < 12) throw new Error('truncated PNG chunk header');
    const length = buffer.readUInt32BE(offset);
    const chunkEnd = offset + 12 + length;
    if (!Number.isSafeInteger(chunkEnd) || chunkEnd > buffer.length) throw new Error('truncated PNG chunk data');

    const type = buffer.toString('ascii', offset + 4, offset + 8);
    if (!/^[A-Za-z]{4}$/.test(type) || type[2] !== type[2].toUpperCase()) {
      throw new Error(`invalid PNG chunk type ${JSON.stringify(type)}`);
    }
    const data = buffer.subarray(offset + 8, offset + 8 + length);
    const expectedCrc = buffer.readUInt32BE(offset + 8 + length);
    const actualCrc = crc32(buffer.subarray(offset + 4, offset + 8 + length));
    if (actualCrc !== expectedCrc) throw new Error(`${type} CRC mismatch`);
    if (!allowedChunks.has(type)) throw new Error(`unsupported PNG chunk ${type}`);
    if (chunkIndex === 0 && type !== 'IHDR') throw new Error('IHDR must be the first PNG chunk');
    if (seenIend) throw new Error('PNG data appears after IEND');

    if (type === 'IHDR') {
      if (ihdr || length !== 13) throw new Error('invalid or duplicate IHDR');
      ihdr = {
        width: data.readUInt32BE(0),
        height: data.readUInt32BE(4),
        bitDepth: data[8],
        colorType: data[9],
        compression: data[10],
        filter: data[11],
        interlace: data[12],
      };
      if (!ihdr.width || !ihdr.height || ihdr.width > 0x7fffffff || ihdr.height > 0x7fffffff) {
        throw new Error('invalid PNG dimensions');
      }
      const validDepths = {
        0: [1, 2, 4, 8, 16],
        2: [8, 16],
        3: [1, 2, 4, 8],
        4: [8, 16],
        6: [8, 16],
      };
      if (!validDepths[ihdr.colorType]?.includes(ihdr.bitDepth)) throw new Error('invalid PNG color type or bit depth');
      if (ihdr.compression !== 0 || ihdr.filter !== 0) throw new Error('unsupported PNG compression or filter method');
      if (ihdr.interlace !== 0) throw new Error('interlaced PNG data is not permitted');
    } else if (!ihdr) {
      throw new Error(`${type} appears before IHDR`);
    } else if (type === 'PLTE') {
      if (palette || seenIdat || !length || length % 3 !== 0 || length > 768) throw new Error('invalid PLTE chunk');
      palette = Buffer.from(data);
    } else if (type === 'tRNS') {
      if (transparency || seenIdat) throw new Error('invalid or misplaced tRNS chunk');
      transparency = Buffer.from(data);
    } else if (['cHRM', 'gAMA', 'sRGB', 'pHYs', 'bKGD', 'tIME'].includes(type)) {
      if (seenSingletonChunks.has(type)) throw new Error(`duplicate ${type} chunk`);
      seenSingletonChunks.add(type);
      if (type === 'cHRM') {
        const chromaticities = length === 32
          ? [...Array(8).keys()].map((index) => data.readUInt32BE(index * 4))
          : [];
        const invalidPair = [0, 2, 4, 6].some(
          (index) => chromaticities[index] + chromaticities[index + 1] > 100000,
        );
        if (
          length !== 32
          || seenIdat
          || palette
          || chromaticities.some((value) => value > 100000)
          || chromaticities[0] === 0
          || chromaticities[1] === 0
          || invalidPair
        ) {
          throw new Error('invalid or misplaced cHRM chunk');
        }
      }
      if (type === 'gAMA' && (length !== 4 || data.readUInt32BE(0) === 0 || seenIdat || palette)) {
        throw new Error('invalid or misplaced gAMA chunk');
      }
      if (type === 'sRGB' && (length !== 1 || data[0] > 3 || seenIdat || palette)) {
        throw new Error('invalid or misplaced sRGB chunk');
      }
      if (type === 'pHYs' && (length !== 9 || data[8] > 1 || seenIdat)) {
        throw new Error('invalid or misplaced pHYs chunk');
      }
      if (type === 'bKGD') {
        const expectedLength = { 0: 2, 2: 6, 3: 1, 4: 2, 6: 6 }[ihdr.colorType];
        const maxSample = ihdr.bitDepth === 16 ? 65535 : (1 << ihdr.bitDepth) - 1;
        const sampleCount = expectedLength === 6 ? 3 : 1;
        const sampleOutOfRange = ihdr.colorType === 3
          ? false
          : [...Array(sampleCount).keys()].some((index) => data.readUInt16BE(index * 2) > maxSample);
        if (
          length !== expectedLength
          || seenIdat
          || sampleOutOfRange
          || (ihdr.colorType === 3 && (!palette || data[0] >= palette.length / 3))
        ) {
          throw new Error('invalid or misplaced bKGD chunk');
        }
      }
      if (type === 'tIME') {
        const year = length === 7 ? data.readUInt16BE(0) : 0;
        const month = data[2];
        const day = data[3];
        const date = new Date(Date.UTC(year, month - 1, day));
        if (
          length !== 7
          || year === 0
          || month < 1
          || month > 12
          || day < 1
          || date.getUTCFullYear() !== year
          || date.getUTCMonth() !== month - 1
          || date.getUTCDate() !== day
          || data[4] > 23
          || data[5] > 59
          || data[6] > 60
        ) {
          throw new Error('invalid tIME chunk');
        }
      }
    } else if (type === 'tEXt') {
      const separator = data.indexOf(0);
      const keyword = separator === -1 ? null : data.subarray(0, separator);
      if (
        !keyword
        || keyword.length < 1
        || keyword.length > 79
        || keyword[0] === 32
        || keyword[keyword.length - 1] === 32
        || keyword.includes(Buffer.from('  '))
        || [...keyword].some((byte) => byte < 32 || (byte > 126 && byte < 161))
      ) {
        throw new Error('invalid tEXt keyword');
      }
    } else if (type === 'IDAT') {
      if (idatEnded) throw new Error('IDAT chunks must be consecutive');
      seenIdat = true;
      idatParts.push(data);
    } else if (type === 'IEND') {
      if (length !== 0 || !seenIdat) throw new Error('invalid IEND or missing IDAT');
      seenIend = true;
    }

    if (seenIdat && type !== 'IDAT' && type !== 'IEND') idatEnded = true;
    offset = chunkEnd;
    chunkIndex += 1;
    if (type === 'IEND') break;
  }

  if (!ihdr || !seenIend || offset !== buffer.length) throw new Error('missing IEND or trailing PNG data');

  const channelsByColorType = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
  const channels = channelsByColorType[ihdr.colorType];
  const paletteEntries = palette ? palette.length / 3 : 0;
  if (ihdr.colorType === 3 && (!palette || paletteEntries > (1 << ihdr.bitDepth))) {
    throw new Error('indexed PNG requires a valid palette');
  }
  if ((ihdr.colorType === 0 || ihdr.colorType === 4) && palette) throw new Error('grayscale PNG cannot contain PLTE');
  if (transparency) {
    const maxSample = ihdr.bitDepth === 16 ? 65535 : (1 << ihdr.bitDepth) - 1;
    const sampleOutOfRange = (
      (ihdr.colorType === 0 && transparency.length === 2 && transparency.readUInt16BE(0) > maxSample)
      || (
        ihdr.colorType === 2
        && transparency.length === 6
        && [0, 2, 4].some((offset) => transparency.readUInt16BE(offset) > maxSample)
      )
    );
    const validTransparency = (
      (ihdr.colorType === 0 && transparency.length === 2)
      || (ihdr.colorType === 2 && transparency.length === 6)
      || (ihdr.colorType === 3 && transparency.length >= 1 && transparency.length <= paletteEntries)
    );
    if (!validTransparency || sampleOutOfRange) throw new Error('invalid tRNS data for PNG color type');
  }

  const bitsPerPixel = channels * ihdr.bitDepth;
  const rowBytes = Math.ceil((ihdr.width * bitsPerPixel) / 8);
  const expectedInflatedLength = ihdr.height * (rowBytes + 1);
  const pixelCount = ihdr.width * ihdr.height;
  if (
    !Number.isSafeInteger(expectedInflatedLength)
    || !Number.isSafeInteger(pixelCount)
    || pixelCount > 10_000_000
  ) {
    throw new Error('PNG dimensions exceed the decoder safety limit');
  }

  let inflated;
  try {
    inflated = zlib.inflateSync(Buffer.concat(idatParts), { maxOutputLength: expectedInflatedLength + 1 });
  } catch (error) {
    throw new Error(`invalid IDAT zlib stream: ${error.message}`);
  }
  if (inflated.length !== expectedInflatedLength) {
    throw new Error(`invalid decoded data length ${inflated.length}; expected ${expectedInflatedLength}`);
  }

  const bytesPerPixel = Math.max(1, Math.ceil(bitsPerPixel / 8));
  const rows = Buffer.alloc(rowBytes * ihdr.height);
  let inputOffset = 0;
  for (let y = 0; y < ihdr.height; y += 1) {
    const filterType = inflated[inputOffset];
    inputOffset += 1;
    if (filterType > 4) throw new Error(`invalid PNG filter type ${filterType}`);
    const row = rows.subarray(y * rowBytes, (y + 1) * rowBytes);
    const previous = y === 0 ? null : rows.subarray((y - 1) * rowBytes, y * rowBytes);
    for (let x = 0; x < rowBytes; x += 1) {
      const encoded = inflated[inputOffset + x];
      const left = x >= bytesPerPixel ? row[x - bytesPerPixel] : 0;
      const above = previous ? previous[x] : 0;
      const upperLeft = previous && x >= bytesPerPixel ? previous[x - bytesPerPixel] : 0;
      let predictor = 0;
      if (filterType === 1) predictor = left;
      else if (filterType === 2) predictor = above;
      else if (filterType === 3) predictor = Math.floor((left + above) / 2);
      else if (filterType === 4) predictor = paeth(left, above, upperLeft);
      row[x] = (encoded + predictor) & 0xff;
    }
    inputOffset += rowBytes;
  }

  const pixels = Buffer.alloc(pixelCount * 4);
  const transparentGray = transparency && ihdr.colorType === 0 ? transparency.readUInt16BE(0) : null;
  const transparentRgb = transparency && ihdr.colorType === 2
    ? [transparency.readUInt16BE(0), transparency.readUInt16BE(2), transparency.readUInt16BE(4)]
    : null;
  for (let y = 0; y < ihdr.height; y += 1) {
    const row = rows.subarray(y * rowBytes, (y + 1) * rowBytes);
    for (let x = 0; x < ihdr.width; x += 1) {
      const sampleOffset = x * channels;
      let red;
      let green;
      let blue;
      let alpha = 255;
      if (ihdr.colorType === 0) {
        const gray = readSample(row, sampleOffset, ihdr.bitDepth);
        red = scaleSample(gray, ihdr.bitDepth);
        green = red;
        blue = red;
        if (transparentGray === gray) alpha = 0;
      } else if (ihdr.colorType === 2) {
        const samples = [0, 1, 2].map((channel) => readSample(row, sampleOffset + channel, ihdr.bitDepth));
        [red, green, blue] = samples.map((sample) => scaleSample(sample, ihdr.bitDepth));
        if (transparentRgb && samples.every((sample, index) => sample === transparentRgb[index])) alpha = 0;
      } else if (ihdr.colorType === 3) {
        const paletteIndex = readSample(row, sampleOffset, ihdr.bitDepth);
        if (paletteIndex >= paletteEntries) throw new Error(`palette index ${paletteIndex} is out of range`);
        red = palette[paletteIndex * 3];
        green = palette[paletteIndex * 3 + 1];
        blue = palette[paletteIndex * 3 + 2];
        if (transparency && paletteIndex < transparency.length) alpha = transparency[paletteIndex];
      } else if (ihdr.colorType === 4) {
        const gray = readSample(row, sampleOffset, ihdr.bitDepth);
        red = scaleSample(gray, ihdr.bitDepth);
        green = red;
        blue = red;
        alpha = scaleSample(readSample(row, sampleOffset + 1, ihdr.bitDepth), ihdr.bitDepth);
      } else {
        red = scaleSample(readSample(row, sampleOffset, ihdr.bitDepth), ihdr.bitDepth);
        green = scaleSample(readSample(row, sampleOffset + 1, ihdr.bitDepth), ihdr.bitDepth);
        blue = scaleSample(readSample(row, sampleOffset + 2, ihdr.bitDepth), ihdr.bitDepth);
        alpha = scaleSample(readSample(row, sampleOffset + 3, ihdr.bitDepth), ihdr.bitDepth);
      }
      const pixelOffset = (y * ihdr.width + x) * 4;
      pixels[pixelOffset] = red;
      pixels[pixelOffset + 1] = green;
      pixels[pixelOffset + 2] = blue;
      pixels[pixelOffset + 3] = alpha;
    }
  }

  return { width: ihdr.width, height: ihdr.height, pixels };
}

function validatePng() {
  const absolute = path.join(ROOT, PNG_ASSET);
  if (!fs.existsSync(absolute)) {
    fail(`${PNG_ASSET}: missing required social-preview PNG`);
    return;
  }
  const buffer = fs.readFileSync(absolute);
  let decoded;
  try {
    decoded = decodePng(buffer);
  } catch (error) {
    fail(`${PNG_ASSET}: PNG decode failed: ${error.message}`);
    return;
  }
  const { width, height } = decoded;
  if (width !== 1280 || height !== 640) fail(`${PNG_ASSET}: expected 1280x640, found ${width}x${height}`);
  if (buffer.length >= PNG_LIMIT) fail(`${PNG_ASSET}: ${buffer.length} bytes exceeds the ${PNG_LIMIT - 1} byte maximum`);
  if (width === 1280 && height === 640 && buffer.length < PNG_LIMIT) {
    console.log(`ok: ${PNG_ASSET} (fully decoded ${width}x${height}, ${buffer.length} bytes)`);
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
    validateAccessibility(root, elements, asset.file);
    validateSafeSvg(source, elements, asset.file);
    validateGeometry(root, elements, asset);
    console.log(`ok: ${asset.file} (XML parsed)`);
  } catch (error) {
    fail(`${asset.file}: XML parse failed: ${error.message}`);
  }
}

validatePng();
validateContrast();

if (failures.length) {
  console.error(`\nBrand asset check failed with ${failures.length} issue${failures.length === 1 ? '' : 's'}:`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`\nBrand asset check passed: ${SVG_ASSETS.length} SVGs, 1 PNG, canonical palette, and WCAG contrast.`);
}
