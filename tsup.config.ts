import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  target: "node20",
  platform: "node",
  dts: true,
  sourcemap: true,
  clean: true,
  // `import.meta.url` is used to locate the Agent SDK's package.json; the shim
  // makes the CommonJS build resolve it from __filename.
  shims: true,
  external: ["@anthropic-ai/claude-agent-sdk"],
});
