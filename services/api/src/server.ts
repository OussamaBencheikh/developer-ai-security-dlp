import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const forbiddenField = /^(?:prompt|secretvalue|fullprompt|sourcecode|password|token|privatekey|authorization|cookie)$/i;
const eventTypePattern = /^[a-z][a-z0-9_]{2,63}$/;
const severityPattern = /^(?:info|low|medium|high|critical)$/;
const actionPattern = /^(?:allowed|warned|blocked|redacted)$/;

export interface ApiOptions {
  readonly allowedOrigin?: string;
  readonly maxRequestsPerMinute?: number;
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status);
  response.end(JSON.stringify(body));
}

function applyHeaders(response: ServerResponse, allowedOrigin: string): void {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const part = Buffer.from(chunk);
    size += part.length;
    if (size > 64 * 1024) throw new Error("payload_too_large");
    chunks.push(part);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function containsForbiddenField(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsForbiddenField);
  return Object.entries(value).some(([key, child]) => forbiddenField.test(key) || containsForbiddenField(child));
}

function isMetadataEvent(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || containsForbiddenField(value)) return false;
  const event = value as Record<string, unknown>;
  const allowedKeys = ["eventType", "secretType", "severity", "action", "service", "extensionVersion", "timestamp"];
  return typeof event.eventType === "string" && eventTypePattern.test(event.eventType)
    && typeof event.secretType === "string" && event.secretType.length <= 80
    && typeof event.severity === "string" && severityPattern.test(event.severity)
    && typeof event.action === "string" && actionPattern.test(event.action)
    && typeof event.service === "string" && event.service.length <= 80
    && typeof event.extensionVersion === "string" && event.extensionVersion.length <= 40
    && Object.keys(event).every((key) => allowedKeys.includes(key));
}

function clientKey(request: IncomingMessage): string {
  const forwarded = request.headers["x-forwarded-for"];
  return typeof forwarded === "string" ? forwarded.split(",")[0]?.trim() || "unknown" : request.socket.remoteAddress ?? "unknown";
}

export function createApiServer(options: ApiOptions = {}) {
  const allowedOrigin = options.allowedOrigin ?? process.env.CORS_ORIGIN ?? "http://localhost:5173";
  const limit = options.maxRequestsPerMinute ?? 60;
  const rateLimits = new Map<string, RateLimitEntry>();
  return createServer(async (request, response) => {
    applyHeaders(response, allowedOrigin);
    if (request.method === "OPTIONS") return send(response, 204, {});
    const key = clientKey(request);
    const now = Date.now();
    const current = rateLimits.get(key);
    if (!current || current.resetAt <= now) rateLimits.set(key, { count: 1, resetAt: now + 60_000 });
    else if (current.count >= limit) {
      response.setHeader("Retry-After", Math.ceil((current.resetAt - now) / 1000));
      return send(response, 429, { error: "rate_limited" });
    } else current.count += 1;

    if (request.method === "GET" && request.url === "/health") return send(response, 200, { status: "ok" });
    if (request.method === "POST" && request.url === "/v1/security-events") {
      try {
        const event = await readJson(request);
        if (!isMetadataEvent(event)) return send(response, 400, { error: "invalid_metadata_event" });
        return send(response, 202, { accepted: true });
      } catch {
        return send(response, 400, { error: "invalid_request" });
      }
    }
    return send(response, 404, { error: "not_found" });
  });
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll("\\", "/")}`) {
  const port = Number(process.env.API_PORT ?? 3000);
  createApiServer().listen(port, () => console.log(`DLP API listening on ${port}`));
}
