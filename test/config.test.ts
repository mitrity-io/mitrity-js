import { describe, expect, it } from "vitest";

import {
  AdmissionError,
  DEFAULT_HOLD_TIMEOUT_MS,
  DEFAULT_TIMEOUT_MS,
  MAX_HOLD_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  parseDurationMs,
  parseLoopbackAddr,
  resolveConfig,
  splitAddr,
  validateAddr,
} from "../src/index.js";

describe("parseDurationMs", () => {
  it.each([
    ["500ms", 500],
    ["9m", 540_000],
    ["1h30m", 5_400_000],
    ["1.5s", 1_500],
    ["540", 540_000],
    ["0", 0],
    ["  2s ", 2_000],
    ["-1s", -1_000],
  ])("parses %s", (value, expected) => {
    expect(parseDurationMs(value, 99)).toBe(expected);
  });

  it.each(["garbage", "", "   ", "1x", "ms", "5m3", undefined])("falls back on %s", (value) => {
    // A misconfigured timeout must not crash a hook and leave a session ungoverned.
    expect(parseDurationMs(value, 7)).toBe(7);
  });
});

describe("addresses", () => {
  it.each([
    ["unix:/run/mitrity/admission.sock", "unix", "/run/mitrity/admission.sock"],
    ["unix:///tmp/a.sock", "unix", "/tmp/a.sock"],
    ["/tmp/a.sock", "unix", "/tmp/a.sock"],
    ["127.0.0.1:8777", "tcp", "127.0.0.1:8777"],
  ])("splits %s", (addr, network, address) => {
    expect(splitAddr(addr)).toEqual({ network, address });
  });

  it.each(["unix:/run/mitrity/admission.sock", "/tmp/x.sock", "127.0.0.1:8777", "[::1]:8777", "localhost:8777"])(
    "accepts %s",
    (addr) => {
      expect(() => validateAddr(addr)).not.toThrow();
    },
  );

  it.each([
    "0.0.0.0:8777",
    ":8777",
    "10.0.0.5:8777",
    "example.com:80",
    "[2001:db8::1]:8777",
    "unix:",
    // URL-authority confusion: a loopback-looking prefix in front of another host.
    "localhost:8777@attacker.example",
    "127.0.0.1:8777@attacker.example:80",
    "127.0.0.1:8777/../x",
    "127.0.0.1:8777?x=1",
    "127.0.0.1:8777#f",
    "127.0.0.1",
    "127.0.0.1:abc",
    "127.0.0.1:0",
    "127.0.0.1:70000",
    "127.0.0.1:8777 ",
    "[::1]:8777@attacker.example",
  ])("refuses %s", (addr) => {
    expect(() => validateAddr(addr)).toThrow(AdmissionError);
  });
});

describe("resolveConfig", () => {
  it("reads the hook's variables", () => {
    const config = resolveConfig({
      env: {
        MITRITY_ADMISSION_ADDR: "unix:/tmp/edge.sock",
        MITRITY_ADMISSION_TOKEN_FILE: "/tmp/edge.token",
        MITRITY_HOOK_TIMEOUT: "250ms",
        MITRITY_HOOK_HOLD_TIMEOUT: "60",
      },
    });
    expect(config).toMatchObject({ addr: "unix:/tmp/edge.sock", tokenFile: "/tmp/edge.token", timeoutMs: 250, holdTimeoutMs: 60_000, network: "unix", address: "/tmp/edge.sock" });
  });

  it("uses platform defaults and explicit values win", () => {
    const config = resolveConfig({ env: {} });
    expect(config.addr).toBeTruthy();
    expect(config.tokenFile).toBeTruthy();
    expect(config.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(config.holdTimeoutMs).toBe(DEFAULT_HOLD_TIMEOUT_MS);
    expect(resolveConfig({ env: { MITRITY_ADMISSION_ADDR: "unix:/a" }, addr: "unix:/b" }).addr).toBe("unix:/b");
  });

  it("clamps timeouts to the hook ceilings", () => {
    const big = resolveConfig({ env: {}, timeoutMs: 10_000_000, holdTimeoutMs: 10_000_000 });
    expect(big.timeoutMs).toBe(MAX_TIMEOUT_MS);
    expect(big.holdTimeoutMs).toBe(MAX_HOLD_TIMEOUT_MS);
    const zero = resolveConfig({ env: {}, timeoutMs: 0, holdTimeoutMs: -5 });
    expect(zero.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(zero.holdTimeoutMs).toBe(0);
  });
});

describe("parseLoopbackAddr", () => {
  it("takes localhost as a spelling of the IPv4 loopback literal and never resolves it", () => {
    expect(parseLoopbackAddr("localhost:8777")).toEqual({ host: "127.0.0.1", port: 8777 });
    expect(parseLoopbackAddr("127.0.0.2:1")).toEqual({ host: "127.0.0.2", port: 1 });
    expect(parseLoopbackAddr("[::1]:8777")).toEqual({ host: "::1", port: 8777 });
    expect(parseLoopbackAddr("[0:0:0:0:0:0:0:1]:8777")).toEqual({ host: "0:0:0:0:0:0:0:1", port: 8777 });
  });
});
