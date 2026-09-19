// Release pre-flight: the tag must name the package version and have a changelog entry.
//
// .github/workflows/release.yml runs this before anything is installed or built. Run it
// by hand before tagging:
//
//     TAG=v0.1.0 node .github/scripts/release-check.js
//
// It checks, in order, that
//
// - package.json's "version" and src/version.ts's VERSION (the adapter_version every
//   attestation reports) both equal the tag without its leading "v";
// - CHANGELOG.md has a dated "## [<version>] - YYYY-MM-DD" section with content.
//
// `--notes-file PATH` writes that section to PATH; the workflow uses it as the notes of
// the GitHub Release. When GITHUB_OUTPUT is set, version=, prerelease= and npm_tag= are
// appended to it. Any failure exits with status 1 and the reason on stderr.

import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

// A final release is X.Y.Z. A semver pre-release (0.2.0-rc.1) is published under the
// `next` dist-tag instead of `latest` and marked as a pre-release on GitHub.
const FINAL_VERSION = /^\d+\.\d+\.\d+$/;
const VERSION_EXPORT = /^export const VERSION = "([^"]+)";$/m;
const LINK_DEFINITION = /^\[[^\]]+\]:\s*\S+/;

function fail(reason) {
  process.stderr.write(`release check: ${reason}\n`);
  process.exit(1);
}

function read(relative) {
  return readFileSync(path.join(root, relative), "utf8");
}

function changelogSection(version) {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const heading = new RegExp(`^## \\[${escaped}\\] - \\d{4}-\\d{2}-\\d{2}$`);
  const body = [];
  let found = false;
  for (const line of read("CHANGELOG.md").split("\n")) {
    if (!found) {
      found = heading.test(line);
      continue;
    }
    if (line.startsWith("## ") || LINK_DEFINITION.test(line)) break;
    body.push(line);
  }
  if (!found) {
    fail(
      `CHANGELOG.md has no "## [${version}] - YYYY-MM-DD" section; ` +
        "add the entry, with the release date, before tagging",
    );
  }
  const text = body.join("\n").trim();
  if (text === "") fail(`the CHANGELOG.md section for ${version} is empty`);
  return `${text}\n`;
}

const args = process.argv.slice(2);
let tag = process.env.TAG || process.env.GITHUB_REF_NAME;
let notesFile;
for (let i = 0; i < args.length; i += 1) {
  const value = args[i + 1];
  if (args[i] === "--tag" && value) {
    tag = value;
    i += 1;
  } else if (args[i] === "--notes-file" && value) {
    notesFile = value;
    i += 1;
  } else {
    fail(`unexpected argument ${args[i]}; usage: release-check.js [--tag vX.Y.Z] [--notes-file PATH]`);
  }
}
if (!tag) fail("no tag: pass --tag vX.Y.Z or set TAG");

const packageVersion = JSON.parse(read("package.json")).version;
if (typeof packageVersion !== "string") fail("package.json has no version");
const sourceVersion = VERSION_EXPORT.exec(read("src/version.ts"))?.[1];
if (sourceVersion === undefined) fail('src/version.ts has no `export const VERSION = "..."`');
if (sourceVersion !== packageVersion) {
  fail(`src/version.ts says ${sourceVersion} but package.json says ${packageVersion}; keep them equal`);
}
if (tag !== `v${packageVersion}`) {
  fail(`tag ${tag} does not match the package version ${packageVersion} (expected v${packageVersion})`);
}

const notes = changelogSection(packageVersion);
const prerelease = !FINAL_VERSION.test(packageVersion);
const npmTag = prerelease ? "next" : "latest";

if (notesFile) writeFileSync(notesFile, notes, "utf8");
if (process.env.GITHUB_OUTPUT) {
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    `version=${packageVersion}\nprerelease=${prerelease}\nnpm_tag=${npmTag}\n`,
    "utf8",
  );
}

const kind = prerelease ? "pre-release, npm tag next" : "final release, npm tag latest";
process.stdout.write(`tag ${tag} matches version ${packageVersion} (${kind})\n`);
process.stdout.write(
  `CHANGELOG.md section for ${packageVersion}: ${notes.trimEnd().split("\n").length} lines\n`,
);
