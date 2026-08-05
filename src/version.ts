import fs from "fs";
import path from "path";

/**
 * One source for what this build calls itself, and for the runtime it claims to support.
 *
 * Both numbers were pasted as literals into the surfaces that report them. `GET /health` and
 * the telemetry scope both answered "0.1.0" after package.json had moved on, so a deployment
 * reported a version that was never released, and `agentwall doctor` compared only the major
 * version against 20, so it told an operator their Node 20 runtime was fine when `npm install`
 * had already refused it under `engines`. A literal copied into three files is three chances
 * to forget one at release time. Reading the manifest means a version bump reaches every
 * surface at once, and the floor is whatever `engines` actually says.
 */

interface Manifest {
  version?: string;
  engines?: { node?: string };
}

// Walks up rather than assuming a depth: the same module is loaded from dist/version.js, from
// dist/routes/ two levels down, and straight from src/ under ts-node, and an installed package
// sits under node_modules/@repsecure/agentwall. The first package.json above this file is the
// one that shipped it in every one of those layouts.
function readManifest(): Manifest {
  let dir = __dirname;
  for (;;) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      try {
        return JSON.parse(fs.readFileSync(candidate, "utf8")) as Manifest;
      } catch {
        return {};
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) return {};
    dir = parent;
  }
}

const manifest = readManifest();

export const packageVersion = manifest.version || "0.0.0";

// `engines.node` is a range such as ">=22.12.0". Only the floor is interesting here, so the
// leading comparator is dropped. A manifest that cannot be read yields "0.0.0", which passes
// every check: a missing file is not evidence that the runtime is too old, and failing the
// doctor on it would send operators chasing their Node version instead of the real problem.
export const nodeFloor = (manifest.engines?.node || "").replace(/^[^0-9]*/, "") || "0.0.0";

/**
 * True when `current` is at or above the declared floor, compared by major, then minor, then
 * patch. A major-only comparison is what let 22.0.0 pass a >=22.12.0 requirement.
 */
export function meetsNodeFloor(current: string = process.versions.node): boolean {
  const have = current.split(".").map((piece) => Number.parseInt(piece, 10) || 0);
  const need = nodeFloor.split(".").map((piece) => Number.parseInt(piece, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    const a = have[i] ?? 0;
    const b = need[i] ?? 0;
    if (a !== b) return a > b;
  }
  return true;
}
