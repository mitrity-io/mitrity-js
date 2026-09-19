/**
 * The admission client: one authenticated request, and the two-phase decision.
 *
 * Every failure — an unreachable socket, a token the edge rejects, a 503, a body that is not a
 * decision, a deadline exceeded — is a rejection from `admit` and a deny from `decide`. There is no
 * path through this module that produces an allow the edge did not send for this request.
 */
import { readFile } from "node:fs/promises";
import http from "node:http";

import {
  ATTEST_TIMEOUT_MS,
  HOLD_MARGIN_MS,
  parseLoopbackAddr,
  resolveConfig,
  validateAddr,
  type AdmissionClientOptions,
  type ResolvedConfig,
} from "./config.js";
import { AdmissionError } from "./errors.js";
import {
  admitRequestToWire,
  attestationToWire,
  decisionFromWire,
  type AdmitRequest,
  type Attestation,
  type Decision,
  type Verdict,
} from "./types.js";

/** The admission protocol this adapter speaks. Sent on every request; nothing else is accepted. */
export const PROTOCOL_VERSION = "1";
export const HEADER_TOKEN = "x-mitrity-admission-token";
export const HEADER_VERSION = "x-mitrity-admission-version";
/** The edge's request-body cap. A larger body is denied here, without sending it. */
export const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const HOST = "mitrity-admission";
const SUMMARY_LIMIT = 200;

export const UNREACHABLE_HINT =
  "This is not a policy decision — the governance edge could not be reached. Check that the MITRITY edge is running and that MITRITY_ADMISSION_ADDR names its admission socket.";

export interface AdmissionLogger {
  debug?: (message: string) => void;
  warn?: (message: string) => void;
}

interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

function summarize(body: Buffer | string): string {
  let text = (typeof body === "string" ? body : body.toString("utf8")).trim();
  text = Array.from(text)
    .map((c) => {
      const code = c.codePointAt(0) ?? 0;
      return code < 0x20 || code === 0x7f ? " " : c;
    })
    .join("");
  return text.length > SUMMARY_LIMIT ? `${text.slice(0, SUMMARY_LIMIT)}…` : text;
}

function reasonOr(body: Buffer): string {
  try {
    const data: unknown = JSON.parse(body.toString("utf8"));
    if (typeof data === "object" && data !== null) {
      for (const key of ["reason", "error"]) {
        const value = (data as Record<string, unknown>)[key];
        if (typeof value === "string" && value !== "") return summarize(value);
      }
    }
  } catch {
    // not JSON: fall through to the bounded summary
  }
  return summarize(body);
}

async function readToken(tokenFile: string): Promise<string> {
  if (tokenFile === "") {
    throw new AdmissionError("config", "no admission token file configured (set MITRITY_ADMISSION_TOKEN_FILE)");
  }
  let raw: string;
  try {
    raw = await readFile(tokenFile, "utf8");
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new AdmissionError(
      "unreachable",
      `admission token file ${JSON.stringify(tokenFile)} could not be read (${detail}): the MITRITY edge is not running here, or is not configured to serve admission`,
      { cause },
    );
  }
  const token = raw.trim();
  if (token === "") throw new AdmissionError("unreachable", `admission token file ${JSON.stringify(tokenFile)} is empty`);
  return token;
}

function encode(body: unknown): Buffer | null {
  if (body === null || body === undefined) return null;
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  if (payload.length > MAX_REQUEST_BYTES) {
    throw new AdmissionError(
      "payload_too_large",
      `the tool input is larger than MITRITY will judge (${payload.length} bytes, cap ${MAX_REQUEST_BYTES})`,
    );
  }
  return payload;
}

function isAbort(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as { code?: unknown }).code;
  return error.name === "AbortError" || error.name === "TimeoutError" || code === "ABORT_ERR";
}

function interpret(response: RawResponse, addr: string): unknown {
  const version = response.headers[HEADER_VERSION];
  const versionValue = Array.isArray(version) ? version[0] : version;
  if (versionValue !== undefined && versionValue !== PROTOCOL_VERSION) {
    throw new AdmissionError(
      "protocol",
      `admission API at ${addr} speaks protocol version ${JSON.stringify(versionValue)}; this adapter speaks ${JSON.stringify(PROTOCOL_VERSION)} — upgrade the edge or the adapter`,
    );
  }
  if (response.status === 204) return null;
  if (response.status === 200 && versionValue === undefined) {
    // Nothing authenticates the edge to the adapter; the version header is the one signal that
    // the peer is a MITRITY edge. A decision without it is not obeyed.
    throw new AdmissionError(
      "protocol",
      `admission API at ${addr} answered without an ${HEADER_VERSION} header — not a MITRITY edge, or a protocol the adapter does not speak`,
    );
  }
  if (response.status === 503) {
    throw new AdmissionError("not_ready", `the MITRITY edge is not ready to judge (${reasonOr(response.body)})`);
  }
  if (response.status === 400) {
    throw new AdmissionError("protocol", `admission API rejected the request (400): ${reasonOr(response.body)}`);
  }
  if (response.status !== 200) {
    throw new AdmissionError("protocol", `admission API returned ${response.status}: ${summarize(response.body)}`);
  }
  try {
    return JSON.parse(response.body.toString("utf8")) as unknown;
  } catch (cause) {
    throw new AdmissionError("protocol", "admission response was not valid JSON", { cause });
  }
}

function verdictFor(decision: Decision): Verdict {
  if (decision.decision === "allow") {
    return {
      allowed: true,
      reason: decision.reason,
      decision,
      error: null,
      updatedInput: decision.updatedInput,
      routedTo: decision.routedTo,
      held: false,
    };
  }
  if (decision.decision === "held") {
    return {
      allowed: false,
      reason: `MITRITY is holding this action for human approval (approval ${decision.approvalId ?? "unknown"}) and it has not been approved. Ask the operator to approve it in the MITRITY console, then try again.`,
      decision,
      error: null,
      updatedInput: null,
      routedTo: null,
      held: true,
    };
  }
  const reason = decision.reason || "MITRITY policy denied this action";
  return {
    allowed: false,
    reason: `MITRITY denied this action: ${reason}`,
    decision,
    error: null,
    updatedInput: null,
    routedTo: null,
    held: false,
  };
}

function unreachableVerdict(error: AdmissionError): Verdict {
  return {
    allowed: false,
    reason: `MITRITY could not authorize this action and blocked it: ${error.message}. ${UNREACHABLE_HINT}`,
    decision: null,
    error,
    updatedInput: null,
    routedTo: null,
    held: false,
  };
}

function holdFailedVerdict(held: Decision, error: AdmissionError): Verdict {
  return {
    allowed: false,
    reason: `MITRITY held this action for human approval (approval ${held.approvalId ?? "unknown"}) and waiting on the approval failed: ${error.message}. The action has not been approved.`,
    decision: held,
    error,
    updatedInput: null,
    routedTo: null,
    held: true,
  };
}

/**
 * Talks to the loopback admission API.
 *
 * Safe to share: it holds configuration only and opens one short-lived connection per request,
 * reading the token file each time so an edge restart is picked up without the caller caring.
 */
export class AdmissionClient {
  readonly config: ResolvedConfig;
  private readonly configError: AdmissionError | null;
  private readonly logger: AdmissionLogger;
  /** The parsed loopback target; the request is built from these, never from the configured string. */
  private readonly target: { socketPath: string } | { host: string; port: number };

  constructor(options: AdmissionClientOptions & { logger?: AdmissionLogger } = {}) {
    this.config = resolveConfig(options);
    this.logger = options.logger ?? {};
    let configError: AdmissionError | null = null;
    try {
      validateAddr(this.config.addr);
    } catch (error) {
      // Not thrown here on purpose: a hook that crashes at construction takes the application
      // down; one that denies every call is what fail-closed means.
      configError = error instanceof AdmissionError ? error : new AdmissionError("config", String(error));
    }
    this.configError = configError;
    this.target =
      this.config.network === "unix"
        ? { socketPath: this.config.address }
        : configError === null
          ? parseLoopbackAddr(this.config.address)
          : { host: "127.0.0.1", port: 1 };
  }

  /** A client configured from the environment alone. */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): AdmissionClient {
    return new AdmissionClient({ env });
  }

  /** Ask for a decision. Rejects with an `AdmissionError` on any failure. */
  async admit(request: AdmitRequest, timeoutMs?: number): Promise<Decision> {
    const started = Date.now();
    const data = await this.request("POST", "/v1/admit", admitRequestToWire(request), timeoutMs ?? this.config.timeoutMs);
    const decision = decisionFromWire(data);
    // The tool input never reaches a log line, and neither does the reason (it names the
    // resolved command). What is logged lines a decision up against the audit trail.
    this.logger.debug?.(
      `admission decision tool=${request.toolName} decision=${decision.decision} admission_id=${decision.admissionId} risk=${decision.riskScore.toFixed(2)} routed_to=${decision.routedTo ?? "-"} ms=${Date.now() - started}`,
    );
    return decision;
  }

  /** Report the runtime's posture. Rejects on failure; the caller logs, never blocks. */
  async attest(attestation: Attestation, timeoutMs?: number): Promise<void> {
    await this.request("POST", "/v1/attest", attestationToWire(attestation), timeoutMs ?? ATTEST_TIMEOUT_MS);
  }

  /** `GET /healthz`, unauthenticated. */
  async health(timeoutMs?: number): Promise<Record<string, unknown>> {
    const data = await this.request("GET", "/healthz", null, timeoutMs ?? this.config.timeoutMs, false);
    return typeof data === "object" && data !== null ? (data as Record<string, unknown>) : {};
  }

  /**
   * The two-phase decision: never rejects, never fabricates an allow.
   *
   * Phase 1 asks with `hold_timeout_seconds: 0` under the deadline. Only a `held` answer starts
   * phase 2, which re-submits with the hold budget so the edge long-polls the approval. Anything
   * that goes wrong on either phase is a deny naming what went wrong.
   */
  async decide(request: AdmitRequest, options: { holdTimeoutMs?: number } = {}): Promise<Verdict> {
    let first: Decision;
    try {
      first = await this.admit({ ...request, holdTimeoutSeconds: 0 });
    } catch (error) {
      return unreachableVerdict(this.asAdmissionError(error));
    }
    if (first.decision !== "held") return verdictFor(first);
    // The caller may cap the configured hold budget for this call; it can never raise it.
    const holdMs =
      options.holdTimeoutMs === undefined ? this.config.holdTimeoutMs : Math.min(this.config.holdTimeoutMs, Math.max(options.holdTimeoutMs, 0));
    const budgetSeconds = Math.floor(holdMs / 1000);
    if (budgetSeconds <= 0) return verdictFor(first);
    try {
      const second = await this.admit({ ...request, holdTimeoutSeconds: budgetSeconds }, budgetSeconds * 1000 + HOLD_MARGIN_MS);
      return verdictFor(second);
    } catch (error) {
      return holdFailedVerdict(first, this.asAdmissionError(error));
    }
  }

  private asAdmissionError(error: unknown): AdmissionError {
    if (error instanceof AdmissionError) return error;
    return new AdmissionError("protocol", `unexpected failure inside the adapter: ${String(error)}`, { cause: error });
  }

  private async request(method: string, path: string, body: unknown, timeoutMs: number, auth = true): Promise<unknown> {
    if (this.configError) throw this.configError;
    const deadline = Date.now() + timeoutMs;
    const payload = encode(body);
    for (let attempt = 1; ; attempt += 1) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new AdmissionError("timeout", "deadline exceeded before the request was sent");
      const token = auth ? await readToken(this.config.tokenFile) : null;
      const response = await this.send(method, path, payload, token, remaining, timeoutMs);
      if (response.status === 401) {
        // Exactly one retry with a freshly-read token: the edge may have restarted and minted a
        // new one. A file that keeps producing 401s is a broken deployment, not something to loop on.
        if (attempt === 1 && deadline - Date.now() > 0) continue;
        throw new AdmissionError("unauthorized", "admission token rejected (401) after re-reading the token file");
      }
      return interpret(response, this.config.addr);
    }
  }

  private send(
    method: string,
    path: string,
    payload: Buffer | null,
    token: string | null,
    remainingMs: number,
    timeoutMs: number,
  ): Promise<RawResponse> {
    const headers: Record<string, string> = { host: HOST, [HEADER_VERSION]: PROTOCOL_VERSION };
    if (token !== null) headers[HEADER_TOKEN] = token;
    if (payload !== null) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(payload.length);
    }
    const target = this.target;
    const signal = AbortSignal.timeout(Math.max(1, Math.floor(remainingMs)));
    return new Promise<RawResponse>((resolve, reject) => {
      const fail = (error: unknown): void => {
        if (isAbort(error)) {
          reject(new AdmissionError("timeout", `admission API at ${this.config.addr} did not answer within ${timeoutMs} ms`, { cause: error }));
          return;
        }
        if (error instanceof AdmissionError) {
          reject(error);
          return;
        }
        const detail = error instanceof Error ? error.message : String(error);
        reject(new AdmissionError("unreachable", `admission API at ${this.config.addr} unreachable: ${detail}`, { cause: error }));
      };
      const req = http.request({ ...target, path, method, headers, signal, agent: false }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            res.destroy();
            fail(new AdmissionError("protocol", "admission response exceeded the size an adapter will read"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) });
        });
        res.on("error", fail);
      });
      req.on("error", fail);
      if (payload !== null) req.write(payload);
      req.end();
    });
  }
}
