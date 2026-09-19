# Changelog

All notable changes to `@mitrity/sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The release
workflow takes a version's section as the notes of its GitHub Release, so every
tag needs a dated `## [X.Y.Z] - YYYY-MM-DD` section (see RELEASING.md).

## [Unreleased]

## [0.1.0] - unreleased

### Added

- `AdmissionClient`: the wire client for the MITRITY edge's admission API
  (`decide()`, `admit()`, `attest()`), with the same edge discovery,
  loopback-only and fail-closed rules as `mitrity-hook`; `AdmissionError` carries
  a `kind` for every failure class.
- `governedOptions()` and `Governor` for the Claude Agent SDK. A `PreToolUse`
  hook admits the execution-capable built-in tools through the edge before they
  run, a `SessionStart` hook attests the runtime's posture, `mcpServers` is
  pinned to the MITRITY gateway, and routed Bash (governed shell) is honored.
- ESM and CommonJS builds with type declarations, for Node 20 or later.
- Conformance tests `C1`–`C20` against an in-process fake edge.

[Unreleased]: https://github.com/mitrity-io/mitrity-js/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mitrity-io/mitrity-js/releases/tag/v0.1.0
