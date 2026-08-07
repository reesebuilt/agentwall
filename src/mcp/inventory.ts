import { z } from "zod";
import type { McpToolDescriptor } from "./types";

export const McpToolDescriptorSchema = z.object({
  name: z.string().min(1),
  title: z.string().optional(),
  description: z.string().optional(),
  inputSchema: z.unknown().optional(),
  outputSchema: z.unknown().optional(),
  annotations: z.record(z.string(), z.unknown()).optional(),
  icons: z.array(z.unknown()).optional(),
  _meta: z.record(z.string(), z.unknown()).optional(),
  meta: z.record(z.string(), z.unknown()).optional(),
});

const McpToolInventoryPageSchema = z.object({
  tools: z.array(McpToolDescriptorSchema.passthrough()),
  nextCursor: z.string().min(1).optional(),
  _meta: z.record(z.string(), z.unknown()).optional(),
}).strict();

export interface McpToolInventoryPage {
  tools: McpToolDescriptor[];
  nextCursor?: string;
}

export type McpToolInventoryParseResult =
  | { status: "not-inventory" }
  | { status: "malformed"; error: string }
  | { status: "valid"; page: McpToolInventoryPage };

export function parseMcpToolInventoryPage(value: unknown): McpToolInventoryParseResult {
  if (value === null || typeof value !== "object" || !Object.prototype.hasOwnProperty.call(value, "tools")) {
    return { status: "not-inventory" };
  }

  const parsed = McpToolInventoryPageSchema.safeParse(value);
  if (!parsed.success) {
    return {
      status: "malformed",
      error: parsed.error.issues
        .map((issue) => `${issue.path.join(".") || "result"}: ${issue.message}`)
        .join("; "),
    };
  }

  return {
    status: "valid",
    page: {
      tools: parsed.data.tools,
      ...(parsed.data.nextCursor === undefined ? {} : { nextCursor: parsed.data.nextCursor }),
    },
  };
}
