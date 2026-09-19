/** Conformance C4, C5, C9: the two-phase decision never fabricates an allow. */
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { AdmissionClient, type AdmitRequest } from "../src/index.js";
import { FakeEdge, allow, deny, held, holdScript } from "./fake-edge.js";

const REQUEST: AdmitRequest = { surface: "custom", toolName: "Bash", toolInput: { command: "rm -rf build" } };

let edge: FakeEdge;
let client: AdmissionClient;

beforeEach(async () => {
  edge = await FakeEdge.start();
  client = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 500, holdTimeoutMs: 2_000 });
});

afterEach(async () => {
  await edge.close();
});

describe("decide", () => {
  it("C4: an unreachable edge is a deny within the deadline", async () => {
    const nobody = new AdmissionClient({ addr: `unix:${path.join(edge.dir, "missing.sock")}`, tokenFile: edge.tokenFile, timeoutMs: 500 });
    const started = Date.now();
    const verdict = await nobody.decide(REQUEST);
    expect(Date.now() - started).toBeLessThan(600);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error?.kind).toBe("unreachable");
    expect(verdict.reason).toContain("not a policy decision");
  });

  it("C5: a late answer is discarded", async () => {
    const impatient = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 300 });
    edge.script({ ...allow(), delayMs: 1_000 });
    const started = Date.now();
    const verdict = await impatient.decide(REQUEST);
    expect(Date.now() - started).toBeLessThan(500);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error?.kind).toBe("timeout");
    expect(edge.admits()).toHaveLength(1);
  });

  it("a policy deny carries the reason and asked with hold_timeout_seconds 0", async () => {
    edge.script(deny());
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error).toBeNull();
    expect(verdict.held).toBe(false);
    expect(verdict.reason).toBe('MITRITY denied this action: policy rule "no destructive commands" denied resolved command: rm');
    expect((edge.admits()[0]!.body as { hold_timeout_seconds: number }).hold_timeout_seconds).toBe(0);
  });

  it("an allow carries updated input and routing", async () => {
    edge.script(allow({ updated_input: { command: "mitrity-hook exec met_1" }, routed_to: "governed_shell" }));
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(true);
    expect(verdict.updatedInput).toEqual({ command: "mitrity-hook exec met_1" });
    expect(verdict.routedTo).toBe("governed_shell");
  });

  it("C9: a hold re-submits with the budget and runs on allow", async () => {
    edge.defaultAdmit = holdScript(allow());
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(true);
    expect(edge.admits().map((r) => (r.body as { hold_timeout_seconds: number }).hold_timeout_seconds)).toEqual([0, 2]);
  });

  it("C9: a deny after the wait names the approval", async () => {
    edge.defaultAdmit = holdScript(deny("approval apr-hold timed out"));
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.error).toBeNull();
    expect(verdict.reason).toContain("apr-hold");
  });

  it("C9: still held after the budget is a deny", async () => {
    edge.defaultAdmit = holdScript(held("apr-hold"));
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.held).toBe(true);
    expect(verdict.reason).toContain("apr-hold");
    expect(verdict.reason).toContain("has not been approved");
  });

  it("C9: a zero hold budget sends no second request", async () => {
    const noWait = new AdmissionClient({ addr: edge.addr, tokenFile: edge.tokenFile, timeoutMs: 500, holdTimeoutMs: 0 });
    edge.defaultAdmit = holdScript(allow());
    const verdict = await noWait.decide(REQUEST);
    expect(verdict.held).toBe(true);
    expect(verdict.allowed).toBe(false);
    expect(edge.admits()).toHaveLength(1);
  });

  it("C9: the hold budget is clamped", () => {
    expect(new AdmissionClient({ addr: "unix:/x", tokenFile: "/t", holdTimeoutMs: 99_999_000 }).config.holdTimeoutMs).toBe(570_000);
  });

  it("C9: a failure while waiting blocks", async () => {
    edge.defaultAdmit = holdScript({ status: 503, body: { reason: "no_profile" } });
    const verdict = await client.decide(REQUEST);
    expect(verdict.allowed).toBe(false);
    expect(verdict.held).toBe(true);
    expect(verdict.error?.kind).toBe("not_ready");
    expect(verdict.reason).toContain("apr-hold");
  });
});
