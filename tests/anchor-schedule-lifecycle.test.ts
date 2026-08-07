import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type * as AnchorServiceModule from "../src/audit/anchor-service";
import type { AnchorPassResult, AnchorPaths } from "../src/audit/anchor-service";

const mockStopAnchorSchedule = jest.fn();
const mockStartAnchorSchedule = jest.fn(
  (
    _paths: AnchorPaths,
    _intervalMs: number,
    _onResult: (result: AnchorPassResult) => void,
    _onError: (error: unknown) => void,
  ) => ({ stop: mockStopAnchorSchedule }),
);

jest.mock("../src/audit/anchor-service", () => {
  const actual = jest.requireActual<typeof AnchorServiceModule>("../src/audit/anchor-service");
  return { ...actual, startAnchorSchedule: mockStartAnchorSchedule };
});

import { loadConfig } from "../src/config";
import { buildServer } from "../src/server";

describe("anchor schedule server lifecycle", () => {
  const tempPaths: string[] = [];

  afterEach(() => {
    jest.restoreAllMocks();
    mockStartAnchorSchedule.mockClear();
    mockStopAnchorSchedule.mockClear();
    delete process.env.AGENTWALL_AUDIT_FILE;
    for (const target of tempPaths.splice(0)) rmSync(target, { recursive: true, force: true });
  });

  it("starts the configured schedule, logs failures, and stops it on close", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentwall-anchor-lifecycle-"));
    tempPaths.push(dir);
    const configPath = join(dir, "agentwall.config.yaml");
    writeFileSync(configPath, "logLevel: silent\naudit:\n  anchorIntervalMs: 1234\n");
    process.env.AGENTWALL_AUDIT_FILE = join(dir, "audit.jsonl");

    const server = await buildServer(loadConfig(configPath));
    const errorLog = jest.spyOn(server.app.log, "error").mockImplementation(() => undefined);
    const call = mockStartAnchorSchedule.mock.calls[0];

    expect(mockStartAnchorSchedule).toHaveBeenCalledTimes(1);
    expect(call[1]).toBe(1234);
    call[3](new Error("calendar unavailable"));
    expect(errorLog).toHaveBeenCalledWith(expect.objectContaining({ err: expect.any(Error) }), "scheduled audit anchor failed");

    await server.app.close();
    expect(mockStopAnchorSchedule).toHaveBeenCalledTimes(1);
  });
});
