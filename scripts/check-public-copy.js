#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const REPOSITORY_ROOT = path.resolve(__dirname, "..");

const CORE_PUBLIC_PATHS = [
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "package.json",
  "docs/README.md",
  "docs/user-guide.md",
  "docs/operator-guide.md",
  "docs/feature-reference.md",
  "docs/glossary.md",
  "docs/install.md",
  "docs/onboarding.md",
  "docs/enforcement.md",
  "docs/threat-model.md",
  "docs/sandbox.md",
  "docs/architecture.md",
  "docs/reference.md",
  "docs/enterprise-roadmap.md",
  "docs/enterprise-controls.md",
];

const PUBLIC_EXTENSIONS = Object.freeze({
  ".md": true,
  ".html": true,
  ".css": true,
  ".js": true,
  ".json": true,
  ".svg": true,
});

const COMPETITOR_NAMES = [
  /\bpipelock\b/giu,
  /\bpipe-lock\b/giu,
  /\bpipe lock\b/giu,
];

const COMPETITOR_URLS = [
  /https?:\/\/[^\s)\]>'"]*(?:pipelock|pipe-lock)[^\s)\]>'"]*/giu,
  /https?:\/\/(?:www\.)?pipelab\.org(?:[/?#][^\s)\]>'"]*)?/giu,
];

const PLACEHOLDERS = [
  /\bTODO\b/gu,
  /\bTBD\b/gu,
  /\bFIXME\b/gu,
  /\bXXX\b/gu,
  /\blorem ipsum\b/giu,
  /\bcoming soon\b/giu,
  /\b(?:insert|replace) (?:copy|content|text) here\b/giu,
  /\{\{\s*(?:TODO|TBD|PLACEHOLDER)\s*\}\}/giu,
];

const RULES = [
  ...COMPETITOR_URLS.map((pattern) => ({ id: "competitor-url", pattern })),
  ...COMPETITOR_NAMES.map((pattern) => ({ id: "competitor-name", pattern })),
  { id: "em-dash", pattern: /—/gu },
  ...PLACEHOLDERS.map((pattern) => ({ id: "placeholder", pattern })),
];

function locationFor(text, index) {
  const before = text.slice(0, index);
  const lines = before.split("\n");
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function scanText(text, file = "<text>") {
  const findings = [];

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    for (const match of text.matchAll(rule.pattern)) {
      const index = match.index ?? 0;
      const location = locationFor(text, index);
      findings.push({
        file,
        rule: rule.id,
        match: match[0],
        line: location.line,
        column: location.column,
      });
    }
  }

  return findings.sort((left, right) => left.line - right.line || left.column - right.column);
}

function walkTextFiles(inputPath, output = []) {
  const stat = fs.statSync(inputPath);
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(inputPath, { withFileTypes: true })) {
      walkTextFiles(path.join(inputPath, entry.name), output);
    }
    return output;
  }

  if (PUBLIC_EXTENSIONS[path.extname(inputPath).toLowerCase()]) {
    output.push(path.resolve(inputPath));
  }
  return output;
}

function defaultPublicFiles() {
  const pathspecs = [...CORE_PUBLIC_PATHS, "public"];
  const result = spawnSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", ...pathspecs],
    { cwd: REPOSITORY_ROOT, encoding: "utf8" }
  );

  if (result.status !== 0) {
    const detail = (result.stderr || "git ls-files failed").trim();
    throw new Error(detail);
  }

  return result.stdout
    .split("\0")
    .filter(Boolean)
    .filter((file) => PUBLIC_EXTENSIONS[path.extname(file).toLowerCase()])
    .map((file) => path.resolve(REPOSITORY_ROOT, file))
    .sort();
}

function resolveInputFiles(args) {
  const files = [];
  if (args.length === 0) {
    files.push(...defaultPublicFiles());
  } else {
    for (const input of args) {
      const resolved = path.resolve(process.cwd(), input);
      if (!fs.existsSync(resolved)) {
        throw new Error(`public copy input does not exist: ${input}`);
      }
      walkTextFiles(resolved, files);
    }
  }

  const uniqueFiles = [...new Set(files)].sort();
  if (uniqueFiles.length === 0) {
    throw new Error("no supported public text files were found");
  }
  return uniqueFiles;
}

function checkFiles(files) {
  const findings = [];
  for (const file of files) {
    findings.push(...scanText(fs.readFileSync(file, "utf8"), path.relative(process.cwd(), file)));
  }
  return findings;
}

function main(args = process.argv.slice(2)) {
  let files;
  try {
    files = resolveInputFiles(args);
  } catch (error) {
    console.error(`Public copy check failed: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }

  const findings = checkFiles(files);
  if (findings.length === 0) {
    console.log(`Public copy check passed for ${files.length} files.`);
    return 0;
  }

  for (const finding of findings) {
    console.error(
      `${finding.file}:${finding.line}:${finding.column}: ${finding.rule}: ${JSON.stringify(finding.match)}`
    );
  }
  console.error(`Public copy check failed with ${findings.length} finding(s).`);
  return 1;
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = {
  COMPETITOR_NAMES,
  COMPETITOR_URLS,
  CORE_PUBLIC_PATHS,
  PLACEHOLDERS,
  checkFiles,
  main,
  resolveInputFiles,
  scanText,
};
