# @mitrity/sdk

MITRITY governance adapter for TypeScript and JavaScript agents: Claude Agent
SDK integration for the MITRITY edge (admission API and gateway).

The MITRITY gateway governs what an agent asks it to do over MCP. It cannot
see what the agent's *framework* does on its own — the Agent SDK's `Bash`,
`Write`, `Edit` and `WebFetch`. This package closes that gap: every such call
is admitted by the co-located edge **before it runs**, with the same policy
rules, command analysis, DLP and holds an MCP call gets, and the same audit
trail (`surface=agent_hook`). If the edge cannot be reached, the call is
denied — there is no fail-open mode.

This package implements the [adapter contract](https://mitrity.com/docs/integrations/adapters)
over the [admission API](https://mitrity.com/docs/integrations/admission-api) wire protocol.

## Install

Until the first npm release, install from git at a pinned ref (a release tag
once one exists, a commit SHA until then). The package builds on install from
a git dependency only if `dist/` is present, so prefer the tarball of a CI
build or wait for the npm release:

```bash
npm install "github:mitrity-io/mitrity-js#<ref>" @anthropic-ai/claude-agent-sdk
```

Node ≥ 20. No runtime dependencies beyond Node's built-ins;
`@anthropic-ai/claude-agent-sdk` is an optional peer dependency (types only).
ESM and CommonJS builds are shipped.

## Prerequisite: a co-located edge

The adapter talks to a `mitrity-gateway` (or `mitrity-mcp-sidecar`) running
next to the agent with an `admission` block:

```yaml
admission:
  enabled: true
  listen_addr: "unix:/run/mitrity/admission.sock"
  token_file: "/run/mitrity/admission.token"
```

It finds the edge through the same environment variables `mitrity-hook` uses,
with the same defaults:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MITRITY_ADMISSION_ADDR` | `unix:/run/mitrity/admission.sock` (`127.0.0.1:8777` on Windows) | The edge's admission listener. Must be a Unix socket or loopback; anything else is refused. |
| `MITRITY_ADMISSION_TOKEN_FILE` | `/run/mitrity/admission.token` | The per-process token the edge writes at startup. |
| `MITRITY_HOOK_TIMEOUT` | `500ms` (max `30s`) | Deadline for one decision. |
| `MITRITY_HOOK_HOLD_TIMEOUT` | `540s` (max `570s`) | Longest to wait on a human approval; `0` disables waiting. |
| `MITRITY_HOOK_FAIL_MODE` | — | Ignored. Adapters have no fail-open mode. |

## Claude Agent SDK

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { governedOptions } from "@mitrity/sdk";

const options = governedOptions({
  gateway: {
    type: "stdio",
    command: "mitrity-gateway",
    args: ["--config", "/etc/mitrity/gateway.yaml"],
  },
  allowedTools: ["Bash", "Read", "Write", "mcp__mitrity"],
  systemPrompt: "You are a careful engineering agent.",
});

for await (const message of query({ prompt: "Clean up the build directory", options })) {
  console.log(message);
}
```

What `governedOptions()` does:

- Installs a `PreToolUse` hook over the execution-capable built-ins (`Bash`,
  `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `WebSearch`) that
  asks the edge before each call. An allow is silent, so your own
  `allowedTools` / `canUseTool` flow still applies on top. A deny reaches the
  model as `permissionDecision: "deny"` with the policy reason. A hold waits
  for a human (up to `MITRITY_HOOK_HOLD_TIMEOUT`) and is a deny if nobody
  approves.
- Installs a `SessionStart` hook that attests the runtime's posture
  (`POST /v1/attest`): which tools are hooked, which are not, other MCP
  servers, permission mode, sandbox settings.
- Pins `mcpServers` to the gateway entry (plus anything you add, which is
  reported as ungoverned), sets `strictMcpConfig: true` and
  `settingSources: []` unless you override them. If you load settings files
  without a strict MCP configuration, the servers they may add are reported
  as `settings:<source>`.
- Keeps every other option you pass. Your own hooks run after MITRITY's; a
  deny from any hook wins.

For statistics or the attestation object, build the `Governor` yourself:

```ts
import { Governor } from "@mitrity/sdk";

const governor = new Governor({ gateway });
const options = governor.options({ allowedTools: ["Bash"] });
// ...
console.log(governor.stats);          // admitted / allowed / denied / held / unreachable / routed
console.log(governor.attestation());  // what the control plane was told
```

### Routed Bash (governed shell)

When the agent's policy sets `builtin_exec_routing: governed_shell`, an
allowed `Bash` comes back with `updated_input` rewriting the command to
`mitrity-hook exec <ticket>`. The adapter emits it as `updatedInput` with an
explicit allow, and the framework runs the relay instead of the model's
command; the gateway executes the judged bytes in its own sandbox. This needs
the `mitrity-hook` binary on `PATH` and a gateway with `exec.enabled: true`.

### Two approval records per hold

The adapter asks twice for a held action: once without waiting (so an
unreachable edge is noticed in milliseconds), then again with the hold budget.
The edge creates an approval for each; resolve whichever is pending. The
stale one times out on its own. This matches `mitrity-hook`.

## The wire client

```ts
import { AdmissionClient } from "@mitrity/sdk";

const client = new AdmissionClient(); // discovers the edge from the environment
const verdict = await client.decide({
  surface: "custom",
  toolName: "Bash",
  toolInput: { command: "rm -rf build" },
});
if (!verdict.allowed) throw new Error(verdict.reason);
```

`decide()` never rejects: it resolves to a `Verdict` whose `reason` is safe to
show the model and whose `error` is set when the deny is the adapter's own
(the edge could not be reached) rather than a policy decision. `admit()` is
the single round trip and rejects with an `AdmissionError` (`kind`:
`config`, `unreachable`, `timeout`, `unauthorized`, `not_ready`, `protocol`,
`payload_too_large`) on any failure.

## What is not governed

- Tools outside the hook matcher. The attestation names them; the MITRITY
  dashboard shows the gap.
- The agent's own code: `child_process.exec` in your application never
  passes a tool boundary. On Linux hosts the MITRITY observer reports it
  after the fact.
- Removing the adapter. It is your code; the control plane detects the
  missing attestation and the silent admission counters, it cannot prevent
  the edit.

## Development

```bash
npm ci
npm run check   # eslint, tsc --noEmit, vitest, tsup
```

Tests run against an in-process fake edge over a Unix socket; no MITRITY
account and no network are needed. The conformance tests are numbered after
the contract (`C1`–`C20`).

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to soc@mitrity.com.

## License

Apache-2.0. Copyright 2026 MITRITY AB.
