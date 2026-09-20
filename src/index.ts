/**
 * MITRITY governance adapter for TypeScript and JavaScript agents.
 *
 * Contract: https://mitrity.com/docs/integrations/adapters
 */
export { VERSION } from "./version.js";
export { canonicalJson, configHash } from "./canonical.js";
export {
  AdmissionClient,
  HEADER_TOKEN,
  HEADER_VERSION,
  MAX_REQUEST_BYTES,
  PROTOCOL_VERSION,
  UNREACHABLE_HINT,
  type AdmissionLogger,
} from "./client.js";
export {
  ATTEST_TIMEOUT_MS,
  DEFAULT_HOLD_TIMEOUT_MS,
  DEFAULT_TIMEOUT_MS,
  ENV_ADDR,
  ENV_FAIL_MODE,
  ENV_HOLD_TIMEOUT,
  ENV_TIMEOUT,
  ENV_TOKEN_FILE,
  HOLD_MARGIN_MS,
  MAX_HOLD_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  parseDurationMs,
  parseLoopbackAddr,
  platformDefaults,
  resolveConfig,
  splitAddr,
  validateAddr,
  type AdmissionClientOptions,
  type Network,
  type ResolvedConfig,
} from "./config.js";
export { AdmissionError, type AdmissionErrorKind } from "./errors.js";
export {
  ADAPTER_NAME,
  EXEC_CAPABLE_TOOLS,
  FRAMEWORK_FOR_SURFACE,
  admitRequestToWire,
  attestationToWire,
  decisionFromWire,
  type AdmitRequest,
  type Attestation,
  type Decision,
  type DecisionKind,
  type SandboxPosture,
  type Surface,
  type Verdict,
} from "./types.js";
export {
  DEFAULT_GATEWAY_NAME,
  FRAMEWORK,
  Governor,
  SURFACE,
  detectFrameworkVersion,
  governedOptions,
  type GovernedOptionsParams,
  type GovernorOptions,
  type GovernorStats,
} from "./claude-agent-sdk.js";
