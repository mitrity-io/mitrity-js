/**
 * An in-process fake of the admission API, served over a Unix socket with `node:http`.
 *
 * It speaks exactly the wire shape of the admission API
 * (https://mitrity.com/docs/integrations/admission-api) and nothing more: token header, version
 * header, `/v1/admit`, `/v1/attest`, `/healthz`. Responses are scripted per test; every request is
 * recorded so a test can assert what the adapter sent — and, just as often, what it did not.
 */
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

export const HEADER_TOKEN = "x-mitrity-admission-token";
export const HEADER_VERSION = "x-mitrity-admission-version";

export interface Recorded {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: unknown;
  raw: Buffer;
}

export interface Scripted {
  status?: number;
  /** A JSON body; use `raw` for bytes that are not JSON. */
  body?: unknown;
  raw?: string;
  delayMs?: number;
  /** The version header to send; `null` sends none. */
  version?: string | null;
}

export type Responder = (request: Recorded) => Scripted;

export function allow(extra: Record<string, unknown> = {}): Scripted {
  return {
    body: {
      decision: "allow",
      reason: "allowed",
      approval_id: null,
      risk_score: 0.1,
      admission_id: "adm-allow",
      updated_input: null,
      ...extra,
    },
  };
}

export function deny(reason = 'policy rule "no destructive commands" denied resolved command: rm'): Scripted {
  return {
    body: { decision: "deny", reason, approval_id: null, risk_score: 0.9, admission_id: "adm-deny", updated_input: null },
  };
}

export function held(approvalId = "apr-1"): Scripted {
  return {
    body: {
      decision: "held",
      reason: "policy requires human approval",
      approval_id: approvalId,
      risk_score: 0.5,
      admission_id: "adm-held",
      updated_input: null,
    },
  };
}

/** Answers `held` to a no-wait request and `outcome` to the waiting one. */
export function holdScript(outcome: Scripted, delayMs = 50, approvalId = "apr-hold"): Responder {
  return (request) => {
    const body = request.body as { hold_timeout_seconds?: number } | null;
    if (body?.hold_timeout_seconds === 0) return held(approvalId);
    return { ...outcome, delayMs };
  };
}

export class FakeEdge {
  readonly dir: string;
  readonly socketPath: string;
  readonly tokenFile: string;
  token: string;
  readonly requests: Recorded[] = [];
  defaultAdmit: Scripted | Responder = allow();
  /** Rotate the token as an edge restart would, right before checking the next request. */
  rotateOnNextRequest = false;
  /** Reject every token regardless of what is presented. */
  rejectAllTokens = false;
  /** The version header on /v1/attest responses; `null` sends none, as the real edge's bare 204 does. */
  defaultAttestVersion: string | null = "1";
  private readonly scripted: (Scripted | Responder)[] = [];
  private readonly server: http.Server;

  private constructor() {
    // AF_UNIX paths are capped at 104 bytes on macOS; keep the socket in a short directory.
    this.dir = mkdtempSync(path.join("/tmp", "me-"));
    this.socketPath = path.join(this.dir, "admission.sock");
    this.tokenFile = path.join(this.dir, "admission.token");
    this.token = this.mint();
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const raw = Buffer.concat(chunks);
        let body: unknown = null;
        if (raw.length > 0) {
          try {
            body = JSON.parse(raw.toString("utf8"));
          } catch {
            body = raw;
          }
        }
        const recorded: Recorded = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body, raw };
        this.requests.push(recorded);
        const response = this.respond(recorded);
        const send = (): void => {
          const payload = response.raw !== undefined ? Buffer.from(response.raw, "utf8") : response.body !== undefined ? Buffer.from(JSON.stringify(response.body), "utf8") : Buffer.alloc(0);
          const headers: Record<string, string> = { "content-length": String(payload.length) };
          if (response.version !== null) headers[HEADER_VERSION] = response.version ?? "1";
          if (payload.length > 0) headers["content-type"] = "application/json";
          res.writeHead(response.status ?? 200, headers);
          res.end(payload);
        };
        if (response.delayMs) setTimeout(send, response.delayMs);
        else send();
      });
    });
  }

  static start(): Promise<FakeEdge> {
    const edge = new FakeEdge();
    return new Promise((resolve, reject) => {
      edge.server.once("error", reject);
      edge.server.listen(edge.socketPath, () => {
        chmodSync(edge.socketPath, 0o600);
        resolve(edge);
      });
    });
  }

  get addr(): string {
    return `unix:${this.socketPath}`;
  }

  /** Queue responses for the next `/v1/admit` calls, in order. */
  script(...responses: (Scripted | Responder)[]): void {
    this.scripted.push(...responses);
  }

  rotateToken(): string {
    this.token = this.mint();
    return this.token;
  }

  admits(): Recorded[] {
    return this.requests.filter((r) => r.path === "/v1/admit");
  }

  attests(): Recorded[] {
    return this.requests.filter((r) => r.path === "/v1/attest");
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.server.closeAllConnections();
      this.server.close(() => {
        rmSync(this.dir, { recursive: true, force: true });
        resolve();
      });
    });
  }

  private mint(): string {
    const token = `tok-${randomBytes(12).toString("hex")}`;
    writeFileSync(this.tokenFile, `${token}\n`, { mode: 0o600 });
    chmodSync(this.tokenFile, 0o600);
    return token;
  }

  private respond(request: Recorded): Scripted {
    if (request.path === "/healthz") return { body: { status: "ok", profile_age_seconds: 3 } };
    if (this.rotateOnNextRequest) {
      this.rotateOnNextRequest = false;
      this.rotateToken();
    }
    if (this.rejectAllTokens || request.headers[HEADER_TOKEN] !== this.token) return { status: 401, version: null };
    const version = request.headers[HEADER_VERSION];
    if (version !== "1") return { status: 400, body: { error: `${HEADER_VERSION} must be "1", got ${JSON.stringify(version)}` } };
    if (request.path === "/v1/attest") return { status: 204, version: this.defaultAttestVersion };
    if (request.path === "/v1/admit") {
      const next = this.scripted.shift() ?? this.defaultAdmit;
      return typeof next === "function" ? next(request) : next;
    }
    return { status: 404, body: { error: "not found" } };
  }
}
