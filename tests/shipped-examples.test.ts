import { describe, expect, it } from "@jest/globals";
import { execFileSync } from "child_process";
import { existsSync, readFileSync } from "fs";
import { dirname, resolve } from "path";
import * as yaml from "js-yaml";

/**
 * Shipped examples must actually load.
 *
 * A config that names a file which is not there is a startup crash for whoever follows
 * the example, and it is trivially checkable, so it is checked here rather than left to
 * be noticed. Renames, deletions, and files that were never committed all produce it.
 *
 * The rule is narrow and mechanical: every path-valued key in a TRACKED example config
 * must resolve to a TRACKED file. Tracked on both sides matters, because an untracked
 * local file satisfying the path hides the breakage from anyone who happens to have one.
 *
 * Paths resolve against the process cwd, not the config file (src/policy/loader.ts uses
 * path.resolve), so they are written repo-root-relative and checked that way here.
 */

function tracked(): string[] {
	return execFileSync("git", ["ls-files"], { cwd: process.cwd(), encoding: "utf8" })
		.split("\n")
		.filter(Boolean);
}

/**
 * INPUT paths: the file must already exist for the config to load. A broken one is a
 * startup crash for anyone who follows the example.
 */
const INPUT_PATH_KEYS = new Set(["configPath", "knowledgeBasePath"]);

/**
 * OUTPUT paths: created at runtime, so absence is correct and expected. They still get
 * a weaker check, because an example that writes to an absolute path outside the working
 * directory would scatter files across a stranger's machine.
 */
const OUTPUT_PATH_KEYS = new Set(["persistencePath", "auditFile", "ledgerPath"]);

function collectPaths(
	node: unknown,
	keys: Set<string>,
	out: string[] = [],
): string[] {
	if (Array.isArray(node)) {
		for (const v of node) collectPaths(v, keys, out);
	} else if (node && typeof node === "object") {
		for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
			if (keys.has(k) && typeof v === "string") out.push(v);
			else collectPaths(v, keys, out);
		}
	}
	return out;
}

describe("shipped examples", () => {
	const files = tracked().filter((f) => f.startsWith("examples/") && f.endsWith(".yaml"));

	it("ships at least one example config, so the check is not vacuously true", () => {
		expect(files.length).toBeGreaterThan(0);
	});

	it.each(files)("%s parses as YAML", (file) => {
		expect(() => yaml.load(readFileSync(file, "utf8"))).not.toThrow();
	});

	it.each(files)("%s reads only files that ship in the repo", (file) => {
		// The crash class this gate exists for: a config naming a policy file that was
		// renamed, deleted, or never committed. Tracked AND present, because an untracked
		// local file satisfying the path hides the breakage from whoever has one.
		const trackedSet = new Set(tracked());
		const broken = collectPaths(yaml.load(readFileSync(file, "utf8")), INPUT_PATH_KEYS).filter(
			(p) => {
				const norm = p.replace(/^\.\//, "");
				return !trackedSet.has(norm) || !existsSync(resolve(process.cwd(), norm));
			},
		);
		expect({ file, broken }).toEqual({ file, broken: [] });
	});

	it.each(files)("%s writes only inside the working directory", (file) => {
		// Output files are created on demand, so they need not exist. They must not be
		// absolute, or escape upward, or an example would litter a stranger's filesystem.
		const escaping = collectPaths(yaml.load(readFileSync(file, "utf8")), OUTPUT_PATH_KEYS).filter(
			(p) => p.startsWith("/") || p.startsWith("~") || p.split("/").includes(".."),
		);
		expect({ file, escaping }).toEqual({ file, escaping: [] });
	});
});

describe("gitignore", () => {
	it("does not ignore any file the repository ships", () => {
		// A bare pattern like `policy.yaml` matches at EVERY depth, so a rule meant for an
		// operator's root-level config can also match a shipped example of the same name.
		// A file tracked before such a rule is added stays tracked, so the breakage is
		// invisible to anyone with an existing clone and real for everyone else.
		// Local-config rules must be anchored with a leading slash.
		const ignored = execFileSync(
			"git",
			["ls-files", "--cached", "--ignored", "--exclude-standard"],
			{ cwd: process.cwd(), encoding: "utf8" },
		)
			.split("\n")
			.filter(Boolean);
		expect(ignored).toEqual([]);
	});
});

describe("shipped docs", () => {
	it("every relative markdown link in tracked docs resolves to a tracked file", () => {
		const trackedSet = new Set(tracked());
		const broken: string[] = [];
		for (const f of tracked().filter((x) => x.endsWith(".md"))) {
			const text = readFileSync(f, "utf8");
			for (const m of text.matchAll(/\]\((?!https?:|mailto:|#)([^)#\s]+)/g)) {
				const target = resolve(dirname(f), m[1]);
				const rel = target.startsWith(process.cwd())
					? target.slice(process.cwd().length + 1)
					: m[1];
				// Directory links are fine when the directory itself ships files.
				const isDir = [...trackedSet].some((t) => t.startsWith(rel.replace(/\/$/, "") + "/"));
				if (!trackedSet.has(rel) && !isDir) broken.push(`${f} -> ${m[1]}`);
			}
		}
		expect(broken).toEqual([]);
	});
});
