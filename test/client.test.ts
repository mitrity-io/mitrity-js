/** Conformance C1–C3, C6, C14, C15, C17, C19: the wire client. */
import { writeFileSync } from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AdmissionClient, AdmissionError, HEADER_TOKEN, HEADER_VERSION, PROTOCOL_VERSION, type AdmitRequest } from "../src/index.js";
import { FakeEdge, type Scripted, allow, deny } from "./fake-edge.js";

const REQUEST: AdmitRequest = { surface: "custom", toolName: "Bash", toolInput: { command: "ls -la" } };

let edge: FakeEdge;
let client: AdmissionClient;

beforeEach(async () => {
  edge = await FakeEdge.start();
  client = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 500, holdTimeoutMs: 2_000 });
});

afterEach(async () => {
  await edge.close();
});

async function rejects(promise: Promise<unknown>, kind: AdmissionError["kind"]): Promise<AdmissionError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AdmissionError);
    expect((error as AdmissionError).kind).toBe(kind);
    return error as AdmissionError;
  }
  throw new Error(`expected an AdmissionError of kind ${kind}`);
}

describe("wire client", () => {
  it("C1: every request carries token, version and content type", async () => {
    const decision = await client.admit(REQUEST);
    expect(decision.decision).toBe("allow");
    const request = edge.admits()[0]!;
    expect(request.headers[HEADER_TOKEN]).toBe(edge.token);
    expect(request.headers[HEADER_VERSION]).toBe(PROTOCOL_VERSION);
    expect(request.headers["content-type"]).toBe("application/json");
    expect(request.headers.host).toBe("mitrity-admission");
    expect(request.body).toEqual({ surface: "custom", tool_name: "Bash", tool_input: { command: "ls -la" } });
  });

  it("C19: the protocol version constant is what is sent", async () => {
    await client.attest({ framework: "custom", adapter: "mitrity-js", adapterVersion: "0.0.0" });
    expect(edge.attests()[0]!.headers[HEADER_VERSION]).toBe("1");
    expect(PROTOCOL_VERSION).toBe("1");
  });

  it("C2: the token is re-read and retried exactly once on 401", async () => {
    const stale = edge.token;
    edge.rotateOnNextRequest = true;
    expect((await client.admit(REQUEST)).decision).toBe("allow");
    expect(edge.admits().map((r) => r.headers[HEADER_TOKEN])).toEqual([stale, edge.token]);
  });

  it("C2: a second 401 is a deny", async () => {
    edge.rejectAllTokens = true;
    await rejects(client.admit(REQUEST), "unauthorized");
    expect(edge.admits()).toHaveLength(2);
  });

  it("C3: a routable address is refused before any I/O", async () => {
    const routable = new AdmissionClient({ addr: "10.0.0.5:8777", tokenFile: edge.tokenFile });
    await rejects(routable.admit(REQUEST), "config");
    const verdict = await routable.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error?.kind).toBe("config");
    expect(edge.requests).toHaveLength(0);
  });

  it("a missing or empty token file is unreachable", async () => {
    const missing = new AdmissionClient({ addr: edge.addr, tokenFile: path.join(edge.dir, "absent.token") });
    await rejects(missing.admit(REQUEST), "unreachable");
    const emptyFile = path.join(edge.dir, "empty.token");
    writeFileSync(emptyFile, "\n");
    const empty = new AdmissionClient({ addr: edge.addr, tokenFile: emptyFile });
    await rejects(empty.admit(REQUEST), "unreachable");
    expect(edge.requests).toHaveLength(0);
  });

  const nonDecisions: [string, Scripted, AdmissionError["kind"]][] = [
    ["400", { status: 400, body: { error: "unknown surface" } }, "protocol"],
    ["503", { status: 503, body: { decision: "deny", reason: "no_profile" } }, "not_ready"],
    ["empty body", { status: 200, raw: "" }, "protocol"],
    ["not json", { status: 200, raw: "not json" }, "protocol"],
    ["unknown decision", { status: 200, body: { decision: "maybe", reason: "x" } }, "protocol"],
    ["wrong version", { status: 200, body: allow().body, version: "2" }, "protocol"],
    ["missing version", { status: 200, body: allow().body, version: null }, "protocol"],
    ["array body", { status: 200, body: [1, 2] }, "protocol"],
    ["500", { status: 500, raw: "boom" }, "protocol"],
  ];
  for (const [label, scripted, kind] of nonDecisions) {
    it(`C6: ${label} is a ${kind} error`, async () => {
      edge.script(scripted);
      await rejects(client.admit(REQUEST), kind);
    });
  }

  it("C6: not-ready carries the edge reason", async () => {
    edge.script({ status: 503, body: { decision: "deny", reason: "no_profile: not primed" } });
    const error = await rejects(client.admit(REQUEST), "not_ready");
    expect(error.message).toContain("no_profile: not primed");
  });

  it("C14: an oversized body is denied without sending", async () => {
    const huge: AdmitRequest = { surface: "custom", toolName: "Write", toolInput: { content: "x".repeat(70 * 1024) } };
    await rejects(client.admit(huge), "payload_too_large");
    const verdict = await client.decide(huge);
    expect(verdict.allowed).toBe(false);
    expect(verdict.reason).toContain("larger than MITRITY will judge");
    expect(edge.requests).toHaveLength(0);
  });

  it("C15: MITRITY_HOOK_FAIL_MODE=open changes nothing", async () => {
    const env = { ...process.env, MITRITY_HOOK_FAIL_MODE: "open" };
    const nobody = new AdmissionClient({ addr: `unix:${path.join(edge.dir, "nobody.sock")}`, tokenFile: edge.tokenFile, env });
    const verdict = await nobody.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error?.kind).toBe("unreachable");
  });

  it("C17: neither the token nor the tool input reaches the log", async () => {
    const lines: string[] = [];
    const logged = new AdmissionClient({
      addr: edge.addr,
      tokenFile: edge.tokenFile,
      logger: { debug: (m) => lines.push(m), warn: (m) => lines.push(m) },
    });
    const marker = "SECRET-INPUT-7f3a";
    await logged.admit({ surface: "custom", toolName: "Bash", toolInput: { command: marker } });
    edge.script(deny(`rule denied ${marker}`));
    await logged.decide({ surface: "custom", toolName: "Bash", toolInput: { command: marker } });
    expect(lines.length).toBeGreaterThan(0);
    const text = lines.join("\n");
    expect(text).not.toContain(marker);
    expect(text).not.toContain(edge.token);
  });

  it("parses every decision field", async () => {
    edge.script(
      allow({
        updated_input: { command: "mitrity-hook exec met_1" },
        routed_to: "governed_shell",
        risk_score: 0.25,
        admission_id: "adm-7",
        reason: "allowed; routed to the governed shell",
      }),
    );
    expect(await client.admit(REQUEST)).toEqual({
      decision: "allow",
      reason: "allowed; routed to the governed shell",
      admissionId: "adm-7",
      riskScore: 0.25,
      approvalId: null,
      updatedInput: { command: "mitrity-hook exec met_1" },
      routedTo: "governed_shell",
    });
  });

  it("validates the request before any I/O", async () => {
    await rejects(client.admit({ surface: "custom", toolName: "   ", toolInput: {} }), "protocol");
    await rejects(client.admit({ surface: "custom", toolName: "Bash", toolInput: {}, holdTimeoutSeconds: -1 }), "protocol");
    await rejects(client.admit({ surface: "nope" as never, toolName: "Bash", toolInput: {} }), "protocol");
    expect(edge.requests).toHaveLength(0);
  });

  it("attest resolves on 204 and sends the wire shape", async () => {
    await client.attest({ framework: "custom", adapter: "mitrity-js", adapterVersion: "0.0.0", hookedTools: ["Bash"], configHash: "ab".repeat(32) });
    expect(edge.attests()[0]!.body).toEqual({
      framework: "custom",
      adapter: "mitrity-js",
      adapter_version: "0.0.0",
      hooked_tools: ["Bash"],
      config_hash: "ab".repeat(32),
    });
  });

  it("attest accepts a 204 without the version header", async () => {
    // The edge answers /v1/attest with a bare 204; only a decision needs the header.
    edge.defaultAttestVersion = null;
    await client.attest({ framework: "custom", adapter: "mitrity-js", adapterVersion: "0" });
    expect(edge.attests()).toHaveLength(1);
  });

  it("health is unauthenticated", async () => {
    expect((await client.health()).status).toBe("ok");
    expect(edge.requests[0]!.headers[HEADER_TOKEN]).toBeUndefined();
  });

  it("accepts a loopback TCP address (connection refused is the unreachable path)", async () => {
    const tcp = new AdmissionClient({ addr: "127.0.0.1:1", tokenFile: edge.tokenFile, timeoutMs: 500 });
    await rejects(tcp.admit(REQUEST), "unreachable");
  });
});
