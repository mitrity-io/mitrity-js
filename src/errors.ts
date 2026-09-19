/**
 * Failures to obtain a decision.
 *
 * Every kind means the same thing at the call site: the tool call is denied.
 * There is no failure the adapter turns into an allow. The kinds exist so a
 * caller can *say why* — an outage reads differently from a policy decision
 * in the model's context — never so it can pick one to ignore.
 */
export type AdmissionErrorKind =
  /** The adapter's own configuration is unusable (a routable address, no token path). Raised before any I/O. */
  | "config"
  /** The edge could not be reached: no socket, connection refused, token file absent or empty. */
  | "unreachable"
  /** The edge did not answer inside the adapter's deadline. */
  | "timeout"
  /** The edge rejected the token after the one permitted re-read and retry. */
  | "unauthorized"
  /** The edge answered 503: it has no mission profile to judge against. */
  | "not_ready"
  /** A 400, a protocol version the adapter does not speak, a body that is not JSON, an unknown decision. */
  | "protocol"
  /** The serialized request body exceeds the edge's 64 KiB cap; denied without sending. */
  | "payload_too_large";

export class AdmissionError extends Error {
  readonly kind: AdmissionErrorKind;

  constructor(kind: AdmissionErrorKind, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AdmissionError";
    this.kind = kind;
  }
}
