/**
 * Governed options for the Claude Agent SDK.
 *
 * The SDK's built-in tools (`Bash`, `Write`, `Edit`, `WebFetch`, ...) never produce an MCP call,
 * so the MITRITY gateway never sees them. This module is what does: a `PreToolUse` hook that admits
 * each call through the co-located edge's admission API before the SDK runs it, a `PostToolUse`
 * hook that keeps the coverage claim honest, and a `SessionStart` hook that attests the runtime's
 * posture. Every guarantee in the adapter contract is implemented here, and the guarantee
 * numbers in the comments (G1–G11) refer to it: https://mitrity.com/docs/integrations/adapters
 *
 * `@anthropic-ai/claude-agent-sdk` is imported for types only; the package is an optional peer.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

import type {
  HookCallback,
  HookCallbackMatcher,
  HookEvent,
  HookJSONOutput,
  McpServerConfig,
  Options,
  SettingSource,
  SyncHookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";

import { configHash } from "./canonical.js";
import { AdmissionClient, type AdmissionLogger } from "./client.js";
import { ATTEST_TIMEOUT_MS, HOLD_MARGIN_MS } from "./config.js";
import { AdmissionError } from "./errors.js";
import { VERSION } from "./version.js";
import { ADAPTER_NAME, EXEC_CAPABLE_TOOLS, type Attestation, type SandboxPosture, type Surface, type Verdict } from "./types.js";

export const SURFACE: Surface = "claude_agent_sdk";
export const FRAMEWORK = "claude-agent-sdk";
export const DEFAULT_GATEWAY_NAME = "mitrity";

const ALL_SETTING_SOURCES: readonly SettingSource[] = ["user", "project", "local"];
const ADMITTED_MEMORY = 4096;
const ATTEST_RETRY_MS = 30_000;
const FRAMEWORK_HOOK_BUDGET_S = 600;
const HOOK_SLACK_S = 30;
const POST_HOOK_TIMEOUT_S = 30;
const REASON_LIMIT = 200;

/** Counters a demo or a dashboard can read. Not the audit trail — the edge keeps that. */
export interface GovernorStats {
  admitted: number;
  allowed: number;
  denied: number;
  held: number;
  unreachable: number;
  routed: number;
  attestations: number;
  unadmittedExecutions: number;
}

export interface GovernorOptions {
  /** The admission client; discovered from the environment when omitted. */
  client?: AdmissionClient;
  /** The co-located gateway's MCP server config; becomes `mcpServers[gatewayName]`. */
  gateway?: McpServerConfig;
  gatewayName?: string;
  /** The built-ins to admit (default: every execution-capable tool). Anything left out is attested as unhooked. */
  hookedTools?: readonly string[];
  /** The Agent SDK version to attest; detected from the installed package when omitted. */
  frameworkVersion?: string;
  logger?: AdmissionLogger;
}

/** `governedOptions()` takes the governor's parameters and any Agent SDK `Options` together. */
export type GovernedOptionsParams = GovernorOptions & Options;

interface Coverage {
  hooked: string[];
  unhooked: string[];
  disallowed: string[];
  mcpServers: string[];
  otherMcpServers: string[];
  permissionMode: string;
  sandbox: SandboxPosture | undefined;
  settingSources: string[];
  strictMcpConfig: boolean;
  extraUnhooked: string[];
}

/** The installed `@anthropic-ai/claude-agent-sdk` version, or `undefined` when it cannot be read. */
export function detectFrameworkVersion(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    const entry = require.resolve("@anthropic-ai/claude-agent-sdk");
    const raw: unknown = JSON.parse(readFileSync(path.join(path.dirname(entry), "package.json"), "utf8"));
    const version = typeof raw === "object" && raw !== null ? (raw as { version?: unknown }).version : undefined;
    return typeof version === "string" ? version : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Bound text that reaches the model's context, as the client bounds error bodies. */
function bound(text: string): string {
  return text.length <= REASON_LIMIT ? text : `${text.slice(0, REASON_LIMIT)}…`;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function optionalBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/**
 * Silent: no `permissionDecision`, so the developer's own permission flow continues (the
 * adapter contract, guarantee G10).
 */
function allow(): SyncHookJSONOutput {
  return {};
}

function deny(reason: string): SyncHookJSONOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

/**
 * Builds governed `Options` and owns the hooks they install.
 *
 * One `Governor` per options object: `options()` computes the coverage the attestation reports,
 * so calling it twice with different overrides would make the second call's attestation describe
 * the first call's options.
 */
export class Governor {
  readonly stats: GovernorStats = {
    admitted: 0,
    allowed: 0,
    denied: 0,
    held: 0,
    unreachable: 0,
    routed: 0,
    attestations: 0,
    unadmittedExecutions: 0,
  };

  readonly client: AdmissionClient;
  readonly gatewayName: string;
  readonly frameworkVersion: string | undefined;
  private readonly gateway: McpServerConfig | undefined;
  private readonly requestedHooks: readonly string[] | undefined;
  private readonly logger: AdmissionLogger;
  private coverage: Coverage | undefined;
  private readonly admitted = new Map<string, true>();
  private readonly attested = new Map<string, string>();
  private readonly attestAttempted = new Map<string, number>();
  private readonly attestInflight = new Set<string>();

  constructor(options: GovernorOptions = {}) {
    this.client = options.client ?? new AdmissionClient();
    this.gateway = options.gateway;
    this.gatewayName = options.gatewayName ?? DEFAULT_GATEWAY_NAME;
    this.requestedHooks = options.hookedTools;
    this.frameworkVersion = options.frameworkVersion ?? detectFrameworkVersion();
    this.logger = options.logger ?? {};
  }

  /**
   * `Options` with MITRITY's hooks and MCP pinning applied. Every override is passed through
   * unchanged except the ones governance has an opinion about: `mcpServers` (merged with the
   * gateway entry), `hooks` (ours run first; a deny from any hook wins), `strictMcpConfig`
   * (default `true`) and `settingSources` (default `[]`).
   */
  options(overrides: Options = {}): Options {
    if (this.coverage !== undefined) {
      throw new Error("Governor.options() builds one options object; create a new Governor");
    }
    const { mcpServers: rawServers, hooks: existingHooks, ...rest } = overrides;

    let mcpServers: Record<string, McpServerConfig> = { ...(rawServers ?? {}) };
    if (this.gateway !== undefined) {
      // The gateway entry owns its name: an override under the same name would silently replace
      // the governed entrance with something else.
      const others = Object.fromEntries(Object.entries(mcpServers).filter(([name]) => name !== this.gatewayName));
      mcpServers = { [this.gatewayName]: this.gateway, ...others };
    }
    const governedName = this.gateway !== undefined ? this.gatewayName : null;
    const other = Object.keys(mcpServers).filter((name) => name !== governedName);

    const strict = rest.strictMcpConfig ?? true;
    const sources: SettingSource[] = rest.settingSources ?? [];
    if (!strict) {
      // Servers those files add are ungoverned paths this adapter did not enumerate; naming the
      // gap is the honest attestation (the adapter contract, guarantee G6).
      for (const source of sources.length > 0 ? sources : ALL_SETTING_SOURCES) other.push(`settings:${source}`);
    }

    const tools = rest.tools;
    const available = new Set(
      Array.isArray(tools) ? EXEC_CAPABLE_TOOLS.filter((tool) => tools.includes(tool)) : EXEC_CAPABLE_TOOLS,
    );
    const disallowed = [...(rest.disallowedTools ?? [])].sort();
    const requested = this.requestedHooks ?? EXEC_CAPABLE_TOOLS;
    const hooked = requested.filter((tool) => available.has(tool));
    // Like the hook, nothing is subtracted here: the control plane subtracts disallowedTools
    // before it raises the finding.
    const unhooked = EXEC_CAPABLE_TOOLS.filter((tool) => available.has(tool) && !hooked.includes(tool));

    const sandboxRaw: unknown = rest.sandbox;
    const sandbox: SandboxPosture | undefined = isRecord(sandboxRaw)
      ? {
          enabled: optionalBoolean(sandboxRaw.enabled),
          allowUnsandboxedCommands: optionalBoolean(sandboxRaw.allowUnsandboxedCommands),
          failIfUnavailable: optionalBoolean(sandboxRaw.failIfUnavailable),
        }
      : undefined;

    this.coverage = {
      hooked,
      unhooked,
      disallowed,
      mcpServers: Object.keys(mcpServers).sort(),
      otherMcpServers: [...new Set(other)].sort(),
      permissionMode: rest.permissionMode ?? "default",
      sandbox,
      settingSources: [...sources],
      strictMcpConfig: strict,
      extraUnhooked: [],
    };

    const hooks: Partial<Record<HookEvent, HookCallbackMatcher[]>> = {};
    if (hooked.length > 0) {
      hooks.PreToolUse = [{ matcher: hooked.join("|"), hooks: [this.preToolUse], timeout: this.hookTimeoutSeconds() }];
    }
    hooks.PostToolUse = [{ hooks: [this.postToolUse], timeout: POST_HOOK_TIMEOUT_S }];
    hooks.SessionStart = [{ hooks: [this.sessionStart], timeout: POST_HOOK_TIMEOUT_S }];
    const extra = existingHooks ?? {};
    for (const event of Object.keys(extra) as HookEvent[]) {
      const matchers = extra[event];
      if (matchers) hooks[event] = [...(hooks[event] ?? []), ...matchers];
    }

    return { ...rest, strictMcpConfig: strict, settingSources: sources, mcpServers, hooks };
  }

  /** The `RuntimeAttestation` for the options this governor built. */
  attestation(permissionMode?: string): Attestation {
    const cov = this.requireCoverage();
    const mode = permissionMode ?? cov.permissionMode;
    const unhooked = [...new Set([...cov.unhooked, ...cov.extraUnhooked])].sort();
    const hooked = [...cov.hooked].sort();
    const hashed = {
      adapter: ADAPTER_NAME,
      adapter_version: VERSION,
      framework: FRAMEWORK,
      framework_version: this.frameworkVersion ?? null,
      hooked_tools: hooked,
      unhooked_exec_tools: unhooked,
      disallowed_tools: cov.disallowed,
      mcp_servers: cov.mcpServers,
      other_mcp_servers: cov.otherMcpServers,
      permission_mode: mode,
      sandbox: cov.sandbox
        ? {
            enabled: cov.sandbox.enabled,
            allow_unsandboxed_commands: cov.sandbox.allowUnsandboxedCommands,
            fail_if_unavailable: cov.sandbox.failIfUnavailable,
          }
        : null,
      setting_sources: cov.settingSources,
      strict_mcp_config: cov.strictMcpConfig,
    };
    return {
      framework: FRAMEWORK,
      frameworkVersion: this.frameworkVersion,
      adapter: ADAPTER_NAME,
      adapterVersion: VERSION,
      hookedTools: hooked,
      unhookedExecTools: unhooked,
      disallowedTools: cov.disallowed,
      otherMcpServers: cov.otherMcpServers,
      permissionMode: mode,
      sandbox: cov.sandbox,
      configHash: configHash(hashed),
    };
  }

  /** Admit one built-in tool call before the SDK runs it. */
  readonly preToolUse: HookCallback = async (input, toolUseID): Promise<HookJSONOutput> => {
    const data = input as unknown as Record<string, unknown>;
    const toolName = typeof data.tool_name === "string" ? data.tool_name : "";
    const callId = toolUseID ?? optionalString(data.tool_use_id);
    let toolInput: Record<string, unknown> = {};
    let verdict: Verdict;
    try {
      await this.ensureAttested(data);
      if (toolName === "") return deny("MITRITY blocked this action: the hook payload carried no tool_name");
      // An MCP tool is the gateway's call to judge (or another server's ungoverned one, already
      // attested); never admitted twice.
      if (toolName.startsWith("mcp__")) return allow();
      toolInput = isRecord(data.tool_input) ? { ...data.tool_input } : {};
      verdict = await this.client.decide({
        surface: SURFACE,
        frameworkVersion: this.frameworkVersion,
        sessionId: optionalString(data.session_id),
        cwd: optionalString(data.cwd),
        toolName,
        toolInput,
        toolUseId: callId,
      }, { holdTimeoutMs: this.holdBudgetMs });
    } catch (error) {
      // A hook that throws leaves the decision to the framework; the adapter decides.
      this.stats.unreachable += 1;
      this.logger.warn?.(`MITRITY: admission of ${toolName} failed inside the adapter: ${String(error)}`);
      return deny(
        `MITRITY could not authorize this action and blocked it: ${bound(String(error))}. This is not a policy decision — the adapter failed before the edge answered.`,
      );
    }

    this.remember(callId);
    this.stats.admitted += 1;
    if (verdict.allowed) {
      this.stats.allowed += 1;
      if (verdict.updatedInput !== null) {
        // Routed (or rewritten): the merged input is what runs, and the explicit allow keeps a
        // human from being prompted about a relay command that carries a ticket (the adapter
        // contract, guarantee G10).
        this.stats.routed += 1;
        if (verdict.routedTo) this.logger.debug?.(`MITRITY routed ${toolName} to ${verdict.routedTo}`);
        return {
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "allow",
            updatedInput: { ...toolInput, ...verdict.updatedInput },
          },
        };
      }
      return allow();
    }
    if (verdict.error !== null) this.stats.unreachable += 1;
    else if (verdict.held) this.stats.held += 1;
    else this.stats.denied += 1;
    const output = deny(verdict.reason);
    if (verdict.held) {
      output.systemMessage = `MITRITY held ${toolName} for human approval and it was not approved within the hold budget (${Math.floor(this.holdBudgetMs / 1000)}s).`;
    }
    return output;
  };

  /** Keep the coverage claim honest: a call that ran without being admitted is a gap. */
  readonly postToolUse: HookCallback = async (input, toolUseID): Promise<HookJSONOutput> => {
    const data = input as unknown as Record<string, unknown>;
    const toolName = typeof data.tool_name === "string" ? data.tool_name : "";
    const callId = toolUseID ?? optionalString(data.tool_use_id);
    try {
      if (callId !== undefined && this.admitted.delete(callId)) return allow();
      if (toolName === "" || toolName.startsWith("mcp__")) return allow();
      const cov = this.coverage;
      if (cov === undefined || !EXEC_CAPABLE_TOOLS.includes(toolName)) return allow();
      this.stats.unadmittedExecutions += 1;
      if (cov.hooked.includes(toolName)) {
        this.logger.warn?.(`MITRITY: ${toolName} ran without passing through the admission hook (tool_use_id=${callId ?? "-"})`);
      } else if (!cov.unhooked.includes(toolName) && !cov.extraUnhooked.includes(toolName)) {
        cov.extraUnhooked.push(toolName);
        this.logger.warn?.(`MITRITY: ${toolName} executed unhooked; re-attesting coverage`);
      }
      await this.ensureAttested(data);
    } catch (error) {
      // PostToolUse can never block; it must never throw either.
      this.logger.warn?.(`MITRITY: post-tool bookkeeping failed: ${String(error)}`);
    }
    return allow();
  };

  /** Attest the runtime's posture when the session starts (the adapter contract, guarantee G6). */
  readonly sessionStart: HookCallback = async (input): Promise<HookJSONOutput> => {
    try {
      await this.ensureAttested(input);
    } catch (error) {
      this.logger.warn?.(`MITRITY: attestation failed: ${String(error)}`);
    }
    return allow();
  };

  /**
   * The hold budget one decision may spend, and the matcher timeout that contains it.
   *
   * The adapter must be the one that answers (the adapter contract, guarantee G3), so every term
   * it can spend inside one PreToolUse — the attestation, the decision deadline, the hold wait,
   * the hold margin — plus slack has to fit under the framework's own 600 s hook budget. The hold
   * budget is what gives when it does not: waiting less on a human is a deny the operator can
   * see; a hook the framework kills is a decision nobody made.
   */
  private budgets(): { holdMs: number; timeoutSeconds: number } {
    const cfg = this.client.config;
    const fixedMs = ATTEST_TIMEOUT_MS + cfg.timeoutMs + HOLD_MARGIN_MS + HOOK_SLACK_S * 1000;
    const holdMs = Math.min(cfg.holdTimeoutMs, Math.max(0, FRAMEWORK_HOOK_BUDGET_S * 1000 - fixedMs));
    return { holdMs, timeoutSeconds: Math.min(FRAMEWORK_HOOK_BUDGET_S, Math.ceil((fixedMs + holdMs) / 1000)) };
  }

  private hookTimeoutSeconds(): number {
    return this.budgets().timeoutSeconds;
  }

  /** Milliseconds one decision may wait on a human approval, after the budget fit. */
  get holdBudgetMs(): number {
    return this.budgets().holdMs;
  }

  /**
   * Attest once per session and config hash; re-attest when either changes. Best effort in the
   * hook's sense: a failed attestation is logged, never a reason to block a call, because its
   * absence is the signal the control plane is built to notice. A failed attempt is retried on
   * later events, but not more often than every 30 s per session.
   */
  private async ensureAttested(data: Record<string, unknown>): Promise<void> {
    const sessionId = optionalString(data.session_id) ?? "";
    const attestation = this.attestation(optionalString(data.permission_mode));
    const digest = attestation.configHash ?? "";
    if (this.attested.get(sessionId) === digest) return;
    const now = Date.now();
    const last = this.attestAttempted.get(sessionId);
    if (last !== undefined && now - last < ATTEST_RETRY_MS && !this.attested.has(sessionId)) return;
    // A burst of concurrent hook calls at session start attests once, not once per call.
    if (this.attestInflight.has(sessionId)) return;
    this.attestAttempted.set(sessionId, now);
    this.attestInflight.add(sessionId);
    try {
      await this.client.attest(attestation);
    } catch (error) {
      const detail = error instanceof AdmissionError ? error.message : String(error);
      this.logger.warn?.(`MITRITY: could not report the runtime posture: ${detail}`);
      return;
    } finally {
      this.attestInflight.delete(sessionId);
    }
    this.attested.set(sessionId, digest);
    this.stats.attestations += 1;
  }

  private requireCoverage(): Coverage {
    if (this.coverage === undefined) throw new Error("call Governor.options() before asking for the attestation");
    return this.coverage;
  }

  private remember(callId: string | undefined): void {
    if (callId === undefined) return;
    this.admitted.set(callId, true);
    while (this.admitted.size > ADMITTED_MEMORY) {
      const oldest = this.admitted.keys().next().value;
      if (oldest === undefined) break;
      this.admitted.delete(oldest);
    }
  }
}

/**
 * Agent SDK `Options` whose built-in tools are admitted by the MITRITY edge.
 *
 * `gateway` is the co-located gateway's MCP server config (usually a stdio entry); it becomes
 * `mcpServers[gatewayName]` and the only governed MCP path. `hookedTools` narrows the admitted
 * built-ins (default: every execution-capable tool); anything left out is attested as unhooked.
 * Every other parameter is an ordinary `Options` field.
 */
export function governedOptions(params: GovernedOptionsParams = {}): Options {
  const { client, gateway, gatewayName, hookedTools, frameworkVersion, logger, ...overrides } = params;
  const governor = new Governor({ client, gateway, gatewayName, hookedTools, frameworkVersion, logger });
  return governor.options(overrides);
}
