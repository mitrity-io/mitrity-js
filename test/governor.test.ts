/**
 * Conformance C7, C8, C10–C13, C16, C18, C20 for the Claude Agent SDK integration.
 *
 * The hooks are exercised directly with the payloads the SDK delivers; no CLI is spawned.
 */
import path from "node:path";

import type { HookCallbackMatcher, HookInput, HookJSONOutput, McpServerConfig } from "@anthropic-ai/claude-agent-sdk";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AdmissionClient, AdmissionError, EXEC_CAPABLE_TOOLS, Governor, VERSION, governedOptions } from "../src/index.js";
import { FakeEdge, allow, deny, held, holdScript } from "./fake-edge.js";

const GATEWAY: McpServerConfig = { type: "stdio", command: "mitrity-gateway", args: ["--config", "/etc/mitrity/gateway.yaml"] };
const CONTEXT = { signal: new AbortController().signal };

function hookInput(
  toolName: string,
  toolInput: Record<string, unknown> = {},
  extra: { event?: string; sessionId?: string; cwd?: string; toolUseId?: string; permissionMode?: string } = {},
): HookInput {
  const payload: Record<string, unknown> = {
    session_id: extra.sessionId ?? "sess-1",
    transcript_path: "/tmp/transcript.jsonl",
    cwd: extra.cwd ?? "/workspace/repo",
    permission_mode: extra.permissionMode ?? "default",
    hook_event_name: extra.event ?? "PreToolUse",
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: extra.toolUseId ?? "toolu_1",
  };
  if (extra.event === "PostToolUse") payload.tool_response = { stdout: "", stderr: "" };
  return payload as unknown as HookInput;
}

function sessionStart(sessionId = "sess-1", permissionMode = "default"): HookInput {
  return {
    session_id: sessionId,
    transcript_path: "/tmp/transcript.jsonl",
    cwd: "/workspace/repo",
    permission_mode: permissionMode,
    hook_event_name: "SessionStart",
    source: "startup",
  } as unknown as HookInput;
}

function specific(output: HookJSONOutput): Record<string, unknown> {
  return (output as { hookSpecificOutput?: Record<string, unknown> }).hookSpecificOutput ?? {};
}

let edge: FakeEdge;
let client: AdmissionClient;

beforeEach(async () => {
  edge = await FakeEdge.start();
  client = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 500, holdTimeoutMs: 2_000 });
});

afterEach(async () => {
  await edge.close();
});

describe("governedOptions", () => {
  it("has the governed shape", () => {
    const options = governedOptions({ client, gateway: GATEWAY, permissionMode: "default" });
    expect(options.mcpServers).toEqual({ mitrity: GATEWAY });
    expect(options.strictMcpConfig).toBe(true);
    expect(options.settingSources).toEqual([]);
    expect(options.permissionMode).toBe("default");
    const pre = options.hooks!.PreToolUse![0]!;
    expect(pre.matcher).toBe(EXEC_CAPABLE_TOOLS.join("|"));
    // attest 5 s + decision 0.5 s + hold 2 s + margin 5 s + slack 30 s
    expect(pre.timeout).toBe(43);
    expect(options.hooks!.PostToolUse![0]!.matcher).toBeUndefined();
    expect(options.hooks!.SessionStart).toHaveLength(1);
  });

  it("keeps developer hooks after ours", () => {
    const theirs: HookCallbackMatcher = { matcher: "Bash", hooks: [() => Promise.resolve({})] };
    const options = governedOptions({ client, gateway: GATEWAY, hooks: { PreToolUse: [theirs] } });
    expect(options.hooks!.PreToolUse).toHaveLength(2);
    expect(options.hooks!.PreToolUse![1]).toBe(theirs);
  });

  it("a governor builds one options object", () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    expect(() => governor.options()).toThrow();
    expect(() => new Governor({ client }).attestation()).toThrow();
  });
});

describe("PreToolUse", () => {
  it("C7/C13: an allow is silent and the request is verbatim", async () => {
    const governor = new Governor({ client, gateway: GATEWAY, frameworkVersion: "0.3.278" });
    governor.options();
    const out = await governor.preToolUse(hookInput("Bash", { command: "ls", description: "list", timeout: 5000 }), "toolu_1", CONTEXT);
    expect(out).toEqual({});
    expect(edge.admits()[0]!.body).toEqual({
      surface: "claude_agent_sdk",
      framework_version: "0.3.278",
      session_id: "sess-1",
      cwd: "/workspace/repo",
      tool_name: "Bash",
      tool_input: { command: "ls", description: "list", timeout: 5000 },
      tool_use_id: "toolu_1",
      hold_timeout_seconds: 0,
    });
    expect(governor.stats.admitted).toBe(1);
    expect(governor.stats.allowed).toBe(1);
  });

  it("C13: argument names are not renamed", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    await governor.preToolUse(hookInput("Bash", { commands: ["ls"] }), "toolu_1", CONTEXT);
    expect((edge.admits()[0]!.body as { tool_input: unknown }).tool_input).toEqual({ commands: ["ls"] });
  });

  it("C8: a deny is expressed in the framework idiom with the reason verbatim", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    edge.script(deny());
    const out = specific(await governor.preToolUse(hookInput("Bash", { command: "rm -rf /" }), "toolu_1", CONTEXT));
    expect(out.hookEventName).toBe("PreToolUse");
    expect(out.permissionDecision).toBe("deny");
    expect(out.permissionDecisionReason).toBe('MITRITY denied this action: policy rule "no destructive commands" denied resolved command: rm');
    expect(governor.stats.denied).toBe(1);
  });

  it("C10: a routed allow emits the merged input with an explicit allow", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    edge.script(allow({ updated_input: { command: "mitrity-hook exec met_1" }, routed_to: "governed_shell" }));
    const out = await governor.preToolUse(hookInput("Bash", { command: "rm -rf build", description: "clean" }), "toolu_1", CONTEXT);
    expect(out).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        updatedInput: { command: "mitrity-hook exec met_1", description: "clean" },
      },
    });
    expect(governor.stats.routed).toBe(1);
  });

  it("held after the budget is a deny with a system message", async () => {
    edge.defaultAdmit = held("apr-9");
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    const out = await governor.preToolUse(hookInput("Bash", { command: "x" }), "t", CONTEXT);
    expect(specific(out).permissionDecision).toBe("deny");
    expect(specific(out).permissionDecisionReason).toContain("apr-9");
    expect((out as { systemMessage?: string }).systemMessage).toContain("human approval");
    expect(governor.stats.held).toBe(1);
  });

  it("an unreachable edge is a deny that says so", async () => {
    const nobody = new AdmissionClient({ addr: `unix:${path.join(edge.dir, "nothing.sock")}`, tokenFile: edge.tokenFile, timeoutMs: 300 });
    const governor = new Governor({ client: nobody, gateway: GATEWAY });
    governor.options();
    const out = specific(await governor.preToolUse(hookInput("Bash", { command: "x" }), "t", CONTEXT));
    expect(out.permissionDecision).toBe("deny");
    expect(out.permissionDecisionReason).toContain("not a policy decision");
    expect(governor.stats.unreachable).toBe(1);
  });

  it("an adapter failure is a deny, not a rejection", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    (client as unknown as { decide: () => Promise<never> }).decide = () => Promise.reject(new Error("boom"));
    const out = specific(await governor.preToolUse(hookInput("Bash", { command: "x" }), "t", CONTEXT));
    expect(out.permissionDecision).toBe("deny");
    expect(out.permissionDecisionReason).toContain("boom");
  });

  it("a missing tool name is a deny", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    expect(specific(await governor.preToolUse(hookInput("", { command: "x" }), "t", CONTEXT)).permissionDecision).toBe("deny");
    expect(edge.admits()).toHaveLength(0);
  });

  it("C20: MCP tools are never admitted here", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    expect(await governor.preToolUse(hookInput("mcp__mitrity__fs:read_file", { path: "/x" }), "t", CONTEXT)).toEqual({});
    expect(edge.admits()).toHaveLength(0);
  });

  it("C16: concurrent calls are independent", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    const outputs = await Promise.all(
      Array.from({ length: 10 }, (_, i) => governor.preToolUse(hookInput("Bash", { command: `echo ${i}` }, { toolUseId: `toolu_${i}` }), `toolu_${i}`, CONTEXT)),
    );
    expect(outputs.every((out) => Object.keys(out).length === 0)).toBe(true);
    const ids = edge.admits().map((r) => (r.body as { tool_use_id: string }).tool_use_id).sort();
    expect(ids).toEqual(Array.from({ length: 10 }, (_, i) => `toolu_${i}`).sort());
    expect(edge.attests()).toHaveLength(1);
  });
});

describe("attestation", () => {
  it("C11: attests once per session on SessionStart with every field", async () => {
    const governor = new Governor({ client, gateway: GATEWAY, frameworkVersion: "0.3.278" });
    governor.options({ sandbox: { enabled: true, allowUnsandboxedCommands: false } });
    await governor.sessionStart(sessionStart(), undefined, CONTEXT);
    await governor.sessionStart(sessionStart(), undefined, CONTEXT);
    await governor.preToolUse(hookInput("Bash", { command: "ls" }), "t", CONTEXT);
    expect(edge.attests()).toHaveLength(1);
    const body = edge.attests()[0]!.body as Record<string, unknown>;
    expect(body.framework).toBe("claude-agent-sdk");
    expect(body.framework_version).toBe("0.3.278");
    expect(body.adapter).toBe("mitrity-js");
    expect(body.adapter_version).toBe(VERSION);
    expect(body.hooked_tools).toEqual([...EXEC_CAPABLE_TOOLS].sort());
    expect(body.unhooked_exec_tools).toBeUndefined();
    expect(body.other_mcp_servers).toBeUndefined();
    expect(body.permission_mode).toBe("default");
    expect(body.sandbox).toEqual({ enabled: true, allow_unsandboxed_commands: false, fail_if_unavailable: null });
    expect(body.config_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(governor.stats.attestations).toBe(1);
    await governor.sessionStart(sessionStart("sess-2"), undefined, CONTEXT);
    expect(edge.attests()).toHaveLength(2);
  });

  it("C12: coverage lists are honest", () => {
    const governor = new Governor({ client, gateway: GATEWAY, hookedTools: ["Bash", "Write"] });
    const options = governor.options({
      disallowedTools: ["WebFetch"],
      mcpServers: { other: { type: "http", url: "https://example.com/mcp" } },
      strictMcpConfig: false,
      settingSources: ["user", "project"],
      sandbox: { enabled: true, allowUnsandboxedCommands: false },
    });
    expect(Object.keys(options.mcpServers!).sort()).toEqual(["mitrity", "other"]);
    const attestation = governor.attestation();
    expect(attestation.hookedTools).toEqual(["Bash", "Write"]);
    // Nothing is subtracted: the control plane subtracts disallowed_tools, as it does for the hook.
    expect(attestation.unhookedExecTools).toEqual(["Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"]);
    expect(attestation.disallowedTools).toEqual(["WebFetch"]);
    expect(attestation.otherMcpServers).toEqual(["other", "settings:project", "settings:user"]);
    expect(attestation.sandbox).toEqual({ enabled: true, allowUnsandboxedCommands: false, failIfUnavailable: null });
  });

  it("C12: non-strict with no sources names every source", () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options({ strictMcpConfig: false });
    expect(governor.attestation().otherMcpServers).toEqual(["settings:local", "settings:project", "settings:user"]);
  });

  it("C12: the tools option removes tools from both lists", () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    const options = governor.options({ tools: ["Bash", "Read"] });
    expect(options.hooks!.PreToolUse![0]!.matcher).toBe("Bash");
    expect(governor.attestation().hookedTools).toEqual(["Bash"]);
    expect(governor.attestation().unhookedExecTools).toEqual([]);
  });

  it("no gateway means every server is other", () => {
    const governor = new Governor({ client });
    governor.options({ mcpServers: { tools: { type: "http", url: "https://example.com" } } });
    expect(governor.attestation().otherMcpServers).toEqual(["tools"]);
  });

  it("C18: a permission mode change re-attests", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    await governor.preToolUse(hookInput("Bash", { command: "ls" }), "t1", CONTEXT);
    await governor.preToolUse(hookInput("Bash", { command: "ls" }, { permissionMode: "bypassPermissions" }), "t2", CONTEXT);
    const bodies = edge.attests().map((r) => r.body as Record<string, unknown>);
    expect(bodies).toHaveLength(2);
    expect(bodies[0]!.config_hash).not.toBe(bodies[1]!.config_hash);
    expect(bodies[1]!.permission_mode).toBe("bypassPermissions");
  });

  it("C18: an unadmitted execution widens unhooked and re-attests", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options({ tools: ["Bash"] });
    await governor.sessionStart(sessionStart(), undefined, CONTEXT);
    expect((edge.attests()[0]!.body as Record<string, unknown>).unhooked_exec_tools).toBeUndefined();
    await governor.postToolUse(hookInput("Write", { file_path: "/x" }, { event: "PostToolUse", toolUseId: "never" }), "never", CONTEXT);
    expect(edge.attests()).toHaveLength(2);
    expect((edge.attests()[1]!.body as Record<string, unknown>).unhooked_exec_tools).toEqual(["Write"]);
    expect(governor.stats.unadmittedExecutions).toBe(1);
  });

  it("PostToolUse of an admitted call is quiet", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    await governor.preToolUse(hookInput("Bash", { command: "ls" }), "toolu_1", CONTEXT);
    expect(await governor.postToolUse(hookInput("Bash", { command: "ls" }, { event: "PostToolUse" }), "toolu_1", CONTEXT)).toEqual({});
    expect(edge.attests()).toHaveLength(1);
    expect(governor.stats.unadmittedExecutions).toBe(0);
  });

  it("an attestation failure never blocks a call", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    (client as unknown as { attest: () => Promise<never> }).attest = () => Promise.reject(new AdmissionError("unreachable", "attest down"));
    expect(await governor.preToolUse(hookInput("Bash", { command: "ls" }), "t", CONTEXT)).toEqual({});
    expect(governor.stats.attestations).toBe(0);
  });
});

describe("hook budget", () => {
  it("fits the framework budget; the hold budget is what gives", async () => {
    const slow = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 30_000, holdTimeoutMs: 570_000 });
    const governor = new Governor({ client: slow, gateway: GATEWAY });
    const options = governor.options();
    expect(options.hooks!.PreToolUse![0]!.timeout).toBe(600);
    expect(governor.holdBudgetMs).toBe(600_000 - (5_000 + 30_000 + 5_000 + 30_000));
    expect(governor.holdBudgetMs).toBeLessThan(slow.config.holdTimeoutMs);
    edge.defaultAdmit = holdScript(allow());
    expect(await governor.preToolUse(hookInput("Bash", { command: "x" }), "t", CONTEXT)).toEqual({});
    const budgets = edge.admits().map((r) => (r.body as { hold_timeout_seconds: number }).hold_timeout_seconds);
    expect(budgets).toEqual([0, Math.floor(governor.holdBudgetMs / 1000)]);
  });

  it("bounds the reason of an adapter failure", async () => {
    const governor = new Governor({ client, gateway: GATEWAY });
    governor.options();
    (client as unknown as { decide: () => Promise<never> }).decide = () => Promise.reject(new Error("x".repeat(5000)));
    const out = specific(await governor.preToolUse(hookInput("Bash", { command: "x" }), "t", CONTEXT));
    expect(String(out.permissionDecisionReason).length).toBeLessThan(400);
  });
});
