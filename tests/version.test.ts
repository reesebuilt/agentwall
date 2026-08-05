import fs from "fs";
import path from "path";
import { describe, expect, it } from "@jest/globals";
import { meetsNodeFloor, nodeFloor, packageVersion } from "../src/version";

/**
 * The version and the supported Node floor are each stated in package.json and reported by
 * surfaces that used to hold their own copy of the number.
 *
 * Both copies were wrong at once. `GET /health` and the telemetry scope answered "0.1.0" long
 * after package.json said otherwise, and `agentwall doctor` compared only the major version
 * against 20, so it passed on Node 20.x and on 22.0.0 while `npm install` refused both under
 * `engines: >=22.12.0`. A tool that tells an operator their runtime is fine, after the install
 * has already disagreed, is worse than one that says nothing.
 */

const manifest = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
) as { version: string; engines: { node: string } };

describe("version", () => {
  it("reports the version package.json declares", () => {
    expect(packageVersion).toBe(manifest.version);
    expect(packageVersion).not.toBe("0.0.0");
  });

  it("reads the floor out of the declared engines range", () => {
    expect(nodeFloor).toBe(manifest.engines.node.replace(/^[^0-9]*/, ""));
  });
});

describe("meetsNodeFloor", () => {
  it("accepts the floor itself and anything above it", () => {
    expect(meetsNodeFloor(nodeFloor)).toBe(true);
    expect(meetsNodeFloor("24.14.1")).toBe(true);
    expect(meetsNodeFloor("99.0.0")).toBe(true);
  });

  it("rejects a version whose major matches but whose minor is below the floor", () => {
    // The whole reason this function exists. A major-only comparison passed 22.0.0 against a
    // 22.12.0 requirement, which is the version range npm refuses to install on.
    const [major] = nodeFloor.split(".");
    expect(meetsNodeFloor(`${major}.0.0`)).toBe(false);
  });

  it("rejects an end-of-life major", () => {
    expect(meetsNodeFloor("20.19.37")).toBe(false);
    expect(meetsNodeFloor("18.20.4")).toBe(false);
  });

  it("compares patch when major and minor are equal", () => {
    const [major, minor, patch] = nodeFloor.split(".").map(Number);
    expect(meetsNodeFloor(`${major}.${minor}.${patch + 1}`)).toBe(true);
    if (patch > 0) {
      expect(meetsNodeFloor(`${major}.${minor}.${patch - 1}`)).toBe(false);
    }
  });

  it("treats a version carrying extra labels as its numeric parts", () => {
    expect(meetsNodeFloor("24.14.1-nightly")).toBe(true);
  });
});
