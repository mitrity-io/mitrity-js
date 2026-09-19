/**
 * RFC 8785 (JSON Canonicalization Scheme) for the values an attestation hashes.
 *
 * Two independent implementations hash the same configuration — this adapter and whatever later
 * checks a runtime against it — so the byte sequence has to be pinned rather than left to a JSON
 * library's defaults. The subset here is what a governed configuration contains: strings,
 * booleans, integers, `null`, arrays and objects. Non-integer numbers are refused on purpose.
 */
import { createHash } from "node:crypto";

const SHORT_ESCAPES: Record<string, string> = {
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
  '"': '\\"',
  "\\": "\\\\",
};

function escape(text: string): string {
  let out = '"';
  for (const char of text) {
    const short = SHORT_ESCAPES[char];
    const code = char.codePointAt(0) ?? 0;
    if (short !== undefined) out += short;
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += char;
  }
  return out + '"';
}

/** Sort key: JCS orders members by the UTF-16 code units of their names. */
function compareUtf16(a: string, b: string): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/** Serialize `value` per RFC 8785: sorted members, no whitespace, minimal escapes. */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new TypeError("canonicalJson does not serialize non-integer numbers");
    return String(value);
  }
  if (typeof value === "string") return escape(value);
  if (Array.isArray(value)) return `[${value.map((inner) => canonicalJson(inner)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, inner]) => inner !== undefined)
      .sort(([a], [b]) => compareUtf16(a, b));
    return `{${entries.map(([key, inner]) => `${escape(key)}:${canonicalJson(inner)}`).join(",")}}`;
  }
  throw new TypeError(`canonicalJson does not serialize ${typeof value}`);
}

/** SHA-256, hex, over the canonical serialization of `value`. */
export function configHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
