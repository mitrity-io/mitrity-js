import { describe, expect, it } from "vitest";

import { canonicalJson, configHash } from "../src/index.js";

describe("canonicalJson", () => {
  it("sorts members and drops whitespace", () => {
    expect(canonicalJson({ b: 1, a: [true, null, "x\n", { z: false, y: 0 }] })).toBe('{"a":[true,null,"x\\n",{"y":0,"z":false}],"b":1}');
  });

  it("keeps unicode literal and escapes control characters", () => {
    expect(canonicalJson({ k: 'é"\\' })).toBe('{"k":"é\\u001f\\"\\\\"}');
  });

  it("orders keys by UTF-16 code units", () => {
    // U+1D11E (a surrogate pair in UTF-16) sorts before U+FF5E under JCS, though after by code point.
    expect(canonicalJson({ "～": 1, "\u{1d11e}": 2 })).toBe('{"\u{1d11e}":2,"～":1}');
  });

  it("refuses non-integer numbers and drops undefined members", () => {
    expect(() => canonicalJson({ risk: 0.5 })).toThrow(TypeError);
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}');
  });
});

describe("configHash", () => {
  it("is sha256 hex and order-independent", () => {
    const digest = configHash({ hooked_tools: ["Bash"], adapter: "mitrity-js" });
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(digest).toBe(configHash({ adapter: "mitrity-js", hooked_tools: ["Bash"] }));
    expect(digest).not.toBe(configHash({ adapter: "mitrity-js", hooked_tools: ["Write"] }));
  });
});
