import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const port = Number(process.env.API_PORT ?? 3000);
const allowedOrigin = process.env.CORS_ORIGIN ?? "http://localhost:5173";
const forbiddenField = /^(?:prompt|secretvalue|fullprompt|sourcecode|password|token|privatekey|authorization|cookie)$/i;

function headers(response: ServerResponse): void {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status);
  response.end(JSON.stringify(body));
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  if (Buffer.concat(chunks).length > 64 * 1024) throw new Error("payload_too_large");
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function isMetadataEvent(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(([key, child]) => {
    if (forbiddenField.test(key)) return false;
    return typeof child !== "object" || child === null || (!Array.isArray(child) && isMetadataEvent(child));
  });
}

const server = createServer(async (request, response) => {
  headers(response);
  if (request.method === "OPTIONS") return send(response, 204, {});
  if (request.method === "GET" && request.url === "/health") return send(response, 200, { status: "ok" });
  if (request.method === "POST" && request.url === "/v1/security-events") {
    try {
      const event = await readJson(request);
      if (!isMetadataEvent(event)) return send(response, 400, { error: "metadata_only" });
      return send(response, 202, { accepted: true });
    } catch {
      return send(response, 400, { error: "invalid_request" });
    }
  }
  return send(response, 404, { error: "not_found" });
});

server.listen(port, () => console.log(`DLP API listening on ${port}`));
