import { afterEach, describe, expect, it } from "@jest/globals";
import { spawnSync, type SpawnSyncReturns } from "child_process";
import { existsSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";

const root = resolve(__dirname, "..");
const checker = join(root, "scripts", "check-readme.js");
const temporaryFiles: string[] = [];
const temporaryDirectories: string[] = [];
let fixtureNumber = 0;

const primaryLogo = "assets/brand/agentwall-logo-primary.svg";
const reverseLogo = "assets/brand/agentwall-logo-reverse.svg";
const manifestImages = [
  "docs/assets/agentwall-console-hero.png",
  "docs/assets/agentwall-approval-in-action.png",
  "docs/assets/agentwall-evidence-verification.png",
];

function themeAwarePicture(): string {
  return [
    "<picture>",
    `  <source media=\"(prefers-color-scheme: dark)\" srcset=\"${reverseLogo}\">`,
    `  <img src=\"${primaryLogo}\" alt=\"Agentwall\">`,
    "</picture>",
  ].join("\n");
}

function imageTargets(): string {
  return manifestImages.map((image, index) => `![Product image ${index + 1}](${image})`).join("\n");
}

function writeRootFixture(markdown: string): string {
  fixtureNumber += 1;
  const file = join(root, `.readme-check-${process.pid}-${fixtureNumber}.md`);
  writeFileSync(file, markdown, "utf8");
  temporaryFiles.push(file);
  return file;
}
function runChecker(file: string): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [checker, file], { cwd: root, encoding: "utf8" });
}

afterEach(() => {
  for (const file of temporaryFiles.splice(0)) {
    if (existsSync(file)) unlinkSync(file);
  }
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("README contract checker", () => {
  it("rejects dark media and the reverse logo when they appear on different source elements", () => {
    const markdown = [
      "<picture>",
      '  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/agentwall-logo-primary.svg">',
      `  <source srcset="${reverseLogo}">`,
      `  <img src="${primaryLogo}" alt="Agentwall">`,
      "</picture>",
      imageTargets(),
    ].join("\n");

    const result = runChecker(writeRootFixture(markdown));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("theme-aware <picture>");
  });

  it("rejects manifest paths that appear only in prose, comments, or code", () => {
    const markdown = [
      themeAwarePicture(),
      `Prose path: ${manifestImages[0]}`,
      `<!-- ${manifestImages[1]} -->`,
      "```text",
      manifestImages[2],
      "```",
    ].join("\n");

    const result = runChecker(writeRootFixture(markdown));

    expect(result.status).toBe(1);
    for (const image of manifestImages) {
      expect(result.stderr).toContain(`${image}: README does not reference this manifest image`);
    }
  });

  it("rejects a supplied README path outside the repository before reading it", () => {
    const directory = mkdtempSync(join(tmpdir(), "agentwall-readme-check-"));
    temporaryDirectories.push(directory);
    const outsideReadme = join(directory, "README.md");
    writeFileSync(outsideReadme, `${themeAwarePicture()}\n${imageTargets()}\n`, "utf8");

    const result = runChecker(outsideReadme);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("README path leaves the repository");
  });

  it("accepts a local target whose name starts with two dots", () => {
    const notes = join(root, "..notes.md");
    if (existsSync(notes)) throw new Error(`${notes} already exists`);
    writeFileSync(notes, "Local notes fixture.\n", "utf8");
    temporaryFiles.push(notes);
    const markdown = `${themeAwarePicture()}\n${imageTargets()}\n[Notes](..notes.md)\n`;

    const result = runChecker(writeRootFixture(markdown));

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("README contract check passed");
  });
});
