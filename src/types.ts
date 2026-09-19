/**
 * Wire types of the admission API, as the adapter sees them. Field names on the wire are the
 * contract's (`tool_name`, `hold_timeout_seconds`); the TypeScript API uses camelCase and maps.
 */
import { AdmissionError } from "./errors.js";

/** The calling framework, as the request names it. Not the audit surface (always `agent_hook`). */
export type Surface = "claude_code" | "claude_agent_sdk" | "langchain" | "openai_agents" | "crewai" | "custom";

export type DecisionKind = "allow" | "deny" | "held";

/** Request `surface` (underscores) to `RuntimeAttestation.framework` (hyphens). */
export const FRAMEWORK_FOR_SURFACE: Readonly<Record<Surface, string>> = {
  claude_code: "claude-code",
  claude_agent_sdk: "claude-agent-sdk",
  langchain: "langchain",
  openai_agents: "openai-agents",
  crewai: "crewai",
  custom: "custom",
};

/**
 * The Claude Code / Agent SDK built-in tools that can change something outside the model's
 * context — the inventory `unhooked_exec_tools` is measured against. `Read`, `Glob` and `Grep`
 * are deliberately absent, as in the hook.
 */
export const EXEC_CAPABLE_TOOLS: readonly string[] = Object.freeze([
  "Bash",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "WebFetch",
  "WebSearch",
]);

export const ADAPTER_NAME = "mitrity-js";

/**
 * One `POST /v1/admit` body. `toolName` and `toolInput` are the framework's, verbatim: nothing is
 * renamed or dropped, so a policy that matches a key on the MCP entrance matches the same key here.
 */
export interface AdmitRequest {
  toolName: string;
  toolInput: Record<string, unknown>;
  surface?: Surface;
  frameworkVersion?: string;
  sessionId?: string;
  cwd?: string;
  toolUseId?: string;
  holdTimeoutSeconds?: number;
}

/**
 * One `POST /v1/admit` response. `held` is not an allow: the caller blocks the tool call and either
 * waits (`AdmissionClient.decide`) or gives up. `updatedInput` is present only on `allow` and MUST
 * be what runs.
 */
export interface Decision {
  decision: DecisionKind;
  reason: string;
  admissionId: string;
  riskScore: number;
  approvalId: string | null;
  updatedInput: Record<string, unknown> | null;
  routedTo: string | null;
}

/**
 * The outcome of the two-phase decision (`AdmissionClient.decide`). Never a rejection.
 *
 * `allowed` is the only field a framework integration needs to branch on. `reason` is the message
 * for the model, phrased so an outage is distinguishable from a policy decision. `error` is set when
 * the deny is the adapter's own (the edge could not be reached or did not answer in time); it is
 * `null` for a policy deny.
 */
export interface Verdict {
  allowed: boolean;
  reason: string;
  decision: Decision | null;
  error: AdmissionError | null;
  updatedInput: Record<string, unknown> | null;
  routedTo: string | null;
  held: boolean;
}

/** The runtime's OS-sandbox configuration; a `null` is evaluated by the control plane as the unsafe default. */
export interface SandboxPosture {
  enabled: boolean | null;
  allowUnsandboxedCommands: boolean | null;
  failIfUnavailable: boolean | null;
}

/** A `RuntimeAttestation`: the runtime's self-report of its governance posture. */
export interface Attestation {
  framework: string;
  adapter: string;
  adapterVersion: string;
  frameworkVersion?: string;
  hookedTools?: readonly string[];
  unhookedExecTools?: readonly string[];
  disallowedTools?: readonly string[];
  otherMcpServers?: readonly string[];
  permissionMode?: string;
  sandbox?: SandboxPosture;
  configHash?: string;
}

export function admitRequestToWire(request: AdmitRequest): Record<string, unknown> {
  const surface = request.surface ?? "custom";
  if (!(surface in FRAMEWORK_FOR_SURFACE)) {
    throw new AdmissionError("protocol", `unknown surface ${JSON.stringify(surface)}`);
  }
  if (request.toolName.trim() === "") throw new AdmissionError("protocol", "toolName is required");
  const body: Record<string, unknown> = {
    surface,
    tool_name: request.toolName,
    tool_input: { ...request.toolInput },
  };
  if (request.frameworkVersion) body.framework_version = request.frameworkVersion;
  if (request.sessionId) body.session_id = request.sessionId;
  if (request.cwd) body.cwd = request.cwd;
  if (request.toolUseId) body.tool_use_id = request.toolUseId;
  if (request.holdTimeoutSeconds !== undefined) {
    if (request.holdTimeoutSeconds < 0) throw new AdmissionError("protocol", "holdTimeoutSeconds must not be negative");
    body.hold_timeout_seconds = request.holdTimeoutSeconds;
  }
  return body;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse a response body, refusing anything that is not a decision. An unrecognized decision value
 * is not a decision; refusing it here is what keeps a future protocol change from being read as an
 * allow.
 */
export function decisionFromWire(data: unknown): Decision {
  if (!isRecord(data)) throw new AdmissionError("protocol", "admission response was not a JSON object");
  const decision = data.decision;
  if (decision !== "allow" && decision !== "deny" && decision !== "held") {
    throw new AdmissionError("protocol", `admission returned an unrecognized decision ${JSON.stringify(decision)}`);
  }
  const updatedInput = data.updated_input;
  if (updatedInput !== undefined && updatedInput !== null && !isRecord(updatedInput)) {
    throw new AdmissionError("protocol", "updated_input was not an object");
  }
  const riskScore = data.risk_score ?? 0;
  if (typeof riskScore !== "number" || !Number.isFinite(riskScore)) {
    throw new AdmissionError("protocol", "risk_score was not a number");
  }
  return {
    decision,
    reason: typeof data.reason === "string" ? data.reason : "",
    admissionId: typeof data.admission_id === "string" ? data.admission_id : "",
    riskScore,
    approvalId: typeof data.approval_id === "string" && data.approval_id !== "" ? data.approval_id : null,
    updatedInput: isRecord(updatedInput) ? { ...updatedInput } : null,
    routedTo: typeof data.routed_to === "string" && data.routed_to !== "" ? data.routed_to : null,
  };
}

export function attestationToWire(attestation: Attestation): Record<string, unknown> {
  const body: Record<string, unknown> = {
    framework: attestation.framework,
    adapter: attestation.adapter,
    adapter_version: attestation.adapterVersion,
  };
  if (attestation.frameworkVersion) body.framework_version = attestation.frameworkVersion;
  const lists: [string, readonly string[] | undefined][] = [
    ["hooked_tools", attestation.hookedTools],
    ["unhooked_exec_tools", attestation.unhookedExecTools],
    ["disallowed_tools", attestation.disallowedTools],
    ["other_mcp_servers", attestation.otherMcpServers],
  ];
  for (const [key, value] of lists) {
    if (value && value.length > 0) body[key] = [...value];
  }
  if (attestation.permissionMode) body.permission_mode = attestation.permissionMode;
  if (attestation.sandbox) {
    body.sandbox = {
      enabled: attestation.sandbox.enabled,
      allow_unsandboxed_commands: attestation.sandbox.allowUnsandboxedCommands,
      fail_if_unavailable: attestation.sandbox.failIfUnavailable,
    };
  }
  if (attestation.configHash) body.config_hash = attestation.configHash;
  return body;
}
