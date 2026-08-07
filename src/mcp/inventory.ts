import { z } from "zod";
import type { McpToolDescriptor } from "./types";

const McpToolDescriptorSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.unknown().optional(),
}).passthrough();

const McpToolInventoryPageSchema = z.object({
  tools: z.array(McpToolDescriptorSchema),
  nextCursor: z.string().optional(),
});

export interface McpToolInventoryPage {
  tools: McpToolDescriptor[];
  nextCursor?: string;
}

export function parseMcpToolInventoryPage(value: unknown): McpToolInventoryPage | null {
  const parsed = McpToolInventoryPageSchema.safeParse(value);
  if (!parsed.success) return null;

  return {
    tools: parsed.data.tools,
    ...(parsed.data.nextCursor === undefined ? {} : { nextCursor: parsed.data.nextCursor }),
  };
}
