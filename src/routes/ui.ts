import { readFile } from "fs/promises";
import * as path from "path";
import { FastifyInstance } from "fastify";

const PUBLIC_DIR = path.resolve(__dirname, "../../public");

const MIME_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};

async function sendAsset(
  reply: {
    type: (value: string) => void;
    send: (value: string | Buffer) => unknown;
    code: (value: number) => { send: (value: unknown) => unknown };
  },
  fileName: string
): Promise<void> {
  const assetPath = path.join(PUBLIC_DIR, fileName);
  try {
    const body = await readFile(assetPath);
    const ext = path.extname(fileName);
    reply.type(MIME_TYPES[ext] ?? "application/octet-stream");
    reply.send(body);
  } catch {
    reply.code(404).send({ error: "Asset not found" });
  }
}

export async function uiRoutes(app: FastifyInstance): Promise<void> {
  app.get("/", async (_req, reply) => {
    await sendAsset(reply, "index.html");
  });

  app.get("/dashboard", async (_req, reply) => {
    await sendAsset(reply, "index.html");
  });

  app.get("/knowledge-base", async (_req, reply) => {
    await sendAsset(reply, "index.html");
  });

  app.get("/dashboard/knowledge-base", async (_req, reply) => {
    await sendAsset(reply, "index.html");
  });

  app.get("/styles.css", async (_req, reply) => {
    await sendAsset(reply, "styles.css");
  });

  app.get("/app.js", async (_req, reply) => {
    await sendAsset(reply, "app.js");
  });

  app.get("/assets/:fileName", async (req, reply) => {
    const { fileName } = req.params as { fileName: string };
    if (!fileName || fileName.includes("..") || fileName.includes("/")) {
      return reply.code(400).send({ error: "Invalid asset path" });
    }
    await sendAsset(reply, path.join("assets", fileName));
  });

  app.get("/assets/brand/:fileName", async (req, reply) => {
    const { fileName } = req.params as { fileName: string };
    if (!fileName || fileName.includes("..") || fileName.includes("/")) {
      return reply.code(400).send({ error: "Invalid brand asset path" });
    }
    await sendAsset(reply, path.join("assets", "brand", fileName));
  });
}
