/**
 * Discovery of the edge: the hook's environment variables, defaults and rules.
 */
import path from "node:path";

import { AdmissionError } from "./errors.js";

export const ENV_ADDR = "MITRITY_ADMISSION_ADDR";
export const ENV_TOKEN_FILE = "MITRITY_ADMISSION_TOKEN_FILE";
export const ENV_TIMEOUT = "MITRITY_HOOK_TIMEOUT";
export const ENV_HOLD_TIMEOUT = "MITRITY_HOOK_HOLD_TIMEOUT";
/** Read for documentation's sake and deliberately ignored: adapters have no fail-open mode. */
export const ENV_FAIL_MODE = "MITRITY_HOOK_FAIL_MODE";

/** Deadline for one decision, in milliseconds. The cached-policy path is sub-millisecond. */
export const DEFAULT_TIMEOUT_MS = 500;
export const MAX_TIMEOUT_MS = 30_000;
/** How long to wait on a human approval, in milliseconds. `0` disables waiting. */
export const DEFAULT_HOLD_TIMEOUT_MS = 540_000;
/** Ceiling sized against the framework's own 600 s hook budget, as for the hook. */
export const MAX_HOLD_TIMEOUT_MS = 570_000;
/** Headroom over the hold budget so the edge's own long-poll can answer first. */
export const HOLD_MARGIN_MS = 5_000;
/** Deadline for `POST /v1/attest`. Nothing is blocked on it, so it may be longer. */
export const ATTEST_TIMEOUT_MS = 5_000;

export type Network = "unix" | "tcp";

export interface AdmissionClientOptions {
  /** The edge's admission listener; `unix:<path>` or a loopback `host:port`. */
  addr?: string;
  /** Path of the per-process token file the edge writes at startup. */
  tokenFile?: string;
  /** Deadline for one decision. Clamped to 30 s. */
  timeoutMs?: number;
  /** Budget for waiting on a human approval. Clamped to 570 s; `0` disables waiting. */
  holdTimeoutMs?: number;
  /** Environment to read defaults from (default: `process.env`). */
  env?: NodeJS.ProcessEnv;
}

export interface ResolvedConfig {
  readonly addr: string;
  readonly tokenFile: string;
  readonly timeoutMs: number;
  readonly holdTimeoutMs: number;
  readonly network: Network;
  readonly address: string;
}

const DURATION_UNITS: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  "µs": 1e-3,
  "μs": 1e-3,
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
};
const DURATION_PART = /(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)/gu;
const BARE_NUMBER = /^[+-]?(\d+(?:\.\d*)?|\.\d+)$/u;

/**
 * The admission address and token path a standard install uses on this platform.
 * A Unix socket wherever one can be dialed; loopback TCP on Windows.
 */
export function platformDefaults(env: NodeJS.ProcessEnv = process.env): { addr: string; tokenFile: string } {
  if (process.platform === "win32") {
    const programData = env.PROGRAMDATA ?? env.ProgramData ?? "C:\\ProgramData";
    return { addr: "127.0.0.1:8777", tokenFile: path.join(programData, "Mitrity", "admission.token") };
  }
  return { addr: "unix:/run/mitrity/admission.sock", tokenFile: "/run/mitrity/admission.token" };
}

/**
 * Parse a Go duration (`500ms`, `9m`, `1h30m`) or a bare number of seconds into milliseconds.
 * Malformed input falls back rather than failing, as the hook's own parser does: a misconfigured
 * timeout must not become a crashed hook and an ungoverned session.
 */
export function parseDurationMs(value: string | undefined, fallbackMs: number): number {
  if (value === undefined) return fallbackMs;
  let text = value.trim();
  if (text === "") return fallbackMs;
  if (BARE_NUMBER.test(text)) return Number(text) * 1_000;
  let sign = 1;
  if (text.startsWith("+") || text.startsWith("-")) {
    sign = text.startsWith("-") ? -1 : 1;
    text = text.slice(1);
  }
  let total = 0;
  let position = 0;
  for (const match of text.matchAll(DURATION_PART)) {
    if (match.index !== position) return fallbackMs;
    const amount = match[1];
    const unit = match[2];
    if (amount === undefined || unit === undefined) return fallbackMs;
    total += Number(amount) * (DURATION_UNITS[unit] ?? 0);
    position = match.index + match[0].length;
  }
  if (position !== text.length || position === 0) return fallbackMs;
  return sign * total;
}

/** Split a configured address into the network and the dial address, as the edge does. */
export function splitAddr(addr: string): { network: Network; address: string } {
  if (addr.startsWith("unix://")) return { network: "unix", address: addr.slice("unix://".length) };
  if (addr.startsWith("unix:")) return { network: "unix", address: addr.slice("unix:".length) };
  if (addr.startsWith("/")) return { network: "unix", address: addr };
  return { network: "tcp", address: addr };
}

// A loopback address is exactly host:port — no userinfo, path, query, fragment or
// whitespace, so nothing an HTTP client could read as a different authority.
const TCP_ADDR = /^(?:\[(?<bracket>[0-9A-Fa-f:.]+)\]|(?<bare>[0-9A-Za-z.-]+)):(?<port>\d{1,5})$/u;

function routable(addr: string): AdmissionError {
  return new AdmissionError(
    "config",
    `${ENV_ADDR}=${JSON.stringify(addr)} is neither loopback nor a Unix socket: the admission API carries the command this agent is about to run and its token, and a routable address would send both to whatever answers there`,
  );
}

/**
 * Parse a loopback `host:port` strictly, returning the literal host and the port.
 *
 * The address is parsed, never sliced: `localhost:8777@attacker.example` has a loopback-looking
 * prefix and an HTTP client would connect to the host after the `@`. Only `host:port` is accepted,
 * the host must be a loopback IP literal — `localhost` is taken as a spelling of `127.0.0.1` and
 * never resolved, so a hosts-file entry cannot point it off-box — and the port must be a number.
 */
export function parseLoopbackAddr(address: string): { host: string; port: number } {
  const match = TCP_ADDR.exec(address);
  if (match?.groups === undefined) {
    throw new AdmissionError(
      "config",
      `${ENV_ADDR}=${JSON.stringify(address)} is not a plain host:port: the admission address may carry no userinfo, path, query, fragment or whitespace`,
    );
  }
  let host = match.groups.bracket ?? match.groups.bare ?? "";
  const port = Number(match.groups.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AdmissionError("config", `${ENV_ADDR}=${JSON.stringify(address)} has an invalid port`);
  }
  if (host === "localhost") host = "127.0.0.1";
  if (!isLoopbackLiteral(host)) throw routable(address);
  return { host, port };
}

function isLoopbackLiteral(host: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(host);
  if (v4) {
    const octets = v4.slice(1).map(Number);
    return octets[0] === 127 && octets.every((o) => o <= 255);
  }
  // ::1 in any of its spellings (no zone, no IPv4-mapped forms).
  const compact = host.toLowerCase().replace(/^(0{1,4}:){0,7}/u, "");
  return /^:*1$/u.test(compact) && host.includes(":") && !host.includes(".");
}

/**
 * Refuse an address that is neither loopback nor a Unix socket.
 *
 * The admission API carries the command the agent is about to run and the token that authorizes
 * judging it. A routable address would send both, in cleartext, to whatever answers there — and
 * then act on its answer. The check is the hook's, applied before any I/O.
 */
export function validateAddr(addr: string): void {
  const { network, address } = splitAddr(addr);
  if (network === "unix") {
    if (address === "") throw new AdmissionError("config", `${ENV_ADDR}=${JSON.stringify(addr)} names no socket path`);
    return;
  }
  parseLoopbackAddr(address);
}

function clamp(value: number, fallback: number, max: number, min = Number.EPSILON): number {
  if (!Number.isFinite(value) || value < min) return fallback;
  return Math.min(value, max);
}

/** Explicit options win over the environment; the environment wins over the platform defaults. */
export function resolveConfig(options: AdmissionClientOptions = {}): ResolvedConfig {
  const env = options.env ?? process.env;
  const defaults = platformDefaults(env);
  const envAddr = env[ENV_ADDR]?.trim();
  const envToken = env[ENV_TOKEN_FILE]?.trim();
  const addr = options.addr ?? (envAddr !== undefined && envAddr !== "" ? envAddr : defaults.addr);
  const tokenFile = options.tokenFile ?? (envToken !== undefined && envToken !== "" ? envToken : defaults.tokenFile);
  const timeoutMs = clamp(
    options.timeoutMs ?? parseDurationMs(env[ENV_TIMEOUT], DEFAULT_TIMEOUT_MS),
    DEFAULT_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
  );
  const holdRaw = options.holdTimeoutMs ?? parseDurationMs(env[ENV_HOLD_TIMEOUT], DEFAULT_HOLD_TIMEOUT_MS);
  const holdTimeoutMs = Number.isFinite(holdRaw) ? Math.min(Math.max(holdRaw, 0), MAX_HOLD_TIMEOUT_MS) : DEFAULT_HOLD_TIMEOUT_MS;
  const { network, address } = splitAddr(addr);
  return { addr, tokenFile, timeoutMs, holdTimeoutMs, network, address };
}
