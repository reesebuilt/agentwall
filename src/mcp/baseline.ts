import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "fs";
import { randomUUID } from "crypto";
import { dirname, resolve } from "path";
import { z } from "zod";

import type {
  McpBaselineKey,
  McpToolDescriptor,
} from "./types";

export type {
  McpBaselineDecision,
  McpBaselineKey,
  McpBaselineMode,
} from "./types";

const STORE_VERSION = 1;

interface StoredBaseline {
  key: McpBaselineKey;
  tools: McpToolDescriptor[];
}

interface BaselineDocument {
  version: typeof STORE_VERSION;
  entries: Record<string, StoredBaseline>;
}

const BaselineKeySchema = z.object({
  agentId: z.string(),
  serverName: z.string(),
  commandHash: z.string().optional(),
});

const ToolDescriptorSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.unknown().optional(),
});

const ToolInventorySchema = z.array(ToolDescriptorSchema);
const BaselineDocumentSchema = z.object({
  version: z.literal(STORE_VERSION),
  entries: z.record(
    z.string(),
    z.object({
      key: BaselineKeySchema,
      tools: ToolInventorySchema,
    }),
  ),
});

function keyId(key: McpBaselineKey): string {
  return JSON.stringify([key.agentId, key.serverName, key.commandHash ?? null]);
}

function sanitizeTools(value: unknown): McpToolDescriptor[] {
  const tools = ToolInventorySchema.parse(value);
  const encoded = JSON.stringify(tools);
  if (encoded === undefined) {
    throw new Error("the tool inventory is not JSON serializable");
  }
  return JSON.parse(encoded) as McpToolDescriptor[];
}

function parseDocument(raw: string): BaselineDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    throw new Error(`JSON parse failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  const document = BaselineDocumentSchema.parse(parsed) as BaselineDocument;
  for (const [id, value] of Object.entries(document.entries)) {
    if (id !== keyId(value.key)) throw new Error("an entry key does not match its identity");
  }
  return document;
}

/** Versioned, atomic JSON storage for accepted MCP tool inventories. */
export class McpBaselineStore {
  readonly path: string;

  constructor(filePath: string) {
    if (filePath.trim().length === 0) throw new Error("MCP baseline file path is empty");
    this.path = resolve(filePath);
  }

  read(key: McpBaselineKey): McpToolDescriptor[] | undefined {
    const document = this.readDocument();
    const stored = document.entries[keyId(key)];
    return stored === undefined ? undefined : sanitizeTools(stored.tools);
  }

  write(key: McpBaselineKey, tools: McpToolDescriptor[]): void {
    const document = this.readDocument();
    const sanitizedKey = BaselineKeySchema.parse(key);
    document.entries[keyId(sanitizedKey)] = {
      key: sanitizedKey,
      tools: sanitizeTools(tools),
    };

    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporaryPath, `${JSON.stringify(document, null, 2)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      renameSync(temporaryPath, this.path);
    } finally {
      rmSync(temporaryPath, { force: true });
    }
  }

  private readDocument(): BaselineDocument {
    if (!existsSync(this.path)) return { version: STORE_VERSION, entries: {} };
    try {
      return parseDocument(readFileSync(this.path, "utf8"));
    } catch (error) {
      throw new Error(
        `MCP baseline file ${this.path} is malformed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
