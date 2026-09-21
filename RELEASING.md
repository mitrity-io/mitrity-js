# Releasing `@mitrity/sdk`

A release is a tag `vX.Y.Z` on a commit of `main`. Pushing it runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which lints,
type-checks, tests and builds the package, publishes the packed tarball to npm
through [trusted publishing](https://docs.npmjs.com/trusted-publishers) (npm
verifies the workflow's OIDC token and signs the provenance attestation; no npm
token exists anywhere), and creates the GitHub Release with the version's
CHANGELOG section as notes and the tarball attached.

## One-time setup (maintainer)

1. **npm account**: two-factor authentication enabled.
2. **Organization `mitrity`**: <https://www.npmjs.com/org/mitrity> must exist
   with your account as an owner; create it at <https://www.npmjs.com/org/create>
   if it does not (free for public packages). `@mitrity/sdk` can only be published
   by members of that organization. The package name was free on 2026-09-19.
3. **Create the package**: npm configures trusted publishing on a package's
   settings page, which exists only once a version has been published. Publish a
   placeholder from your own logged-in session, so that the real `0.1.0` is the
   first version built and signed by the workflow (no token is stored anywhere):

   ```bash
   mkdir -p /tmp/mitrity-sdk-placeholder && cd /tmp/mitrity-sdk-placeholder
   cat > package.json <<'EOF'
   {
     "name": "@mitrity/sdk",
     "version": "0.0.0",
     "description": "Placeholder that creates the package; the first release is 0.1.0.",
     "license": "Apache-2.0",
     "repository": { "type": "git", "url": "git+https://github.com/mitrity-io/mitrity-js.git" }
   }
   EOF
   npm login                    # browser sign-in with 2FA
   npm publish --access public
   npm deprecate @mitrity/sdk@0.0.0 "Placeholder that created the package; install 0.1.0 or later."
   npm logout
   ```

   If npm lets you configure a trusted publisher for a package that has not been
   published yet by the time you do this, do that instead and skip the
   placeholder.
4. **Trusted publisher**: <https://www.npmjs.com/package/@mitrity/sdk/access> →
   "Trusted publisher" → GitHub Actions:

   | Field | Value |
   | --- | --- |
   | Organization or user | `mitrity-io` |
   | Repository | `mitrity-js` |
   | Workflow filename | `release.yml` |
   | Environment name | `npm` |

5. **Publishing access**, same page: "Require two-factor authentication and
   disallow tokens". Trusted publishing keeps working; every token-based publish
   is refused from then on.
6. **GitHub environment `npm`**: repository Settings → Environments → New
   environment → `npm`. Under "Deployment branches and tags" choose "Selected
   branches and tags" and add the tag rule `v*`, so no branch can ever use the
   environment. Required reviewers are available on public repositories (and on
   private ones only with GitHub Enterprise): once the repository is public, add
   yourself as a required reviewer so every publish waits for one approval click.
7. **Tag ruleset (recommended)**: Settings → Rules → Rulesets → New tag ruleset
   for `v*` that restricts creation, update and deletion to repository admins.
   Whoever can push a matching tag can publish.

## Each release

1. Branch from `origin/main`:
   `git fetch origin && git switch -c release/vX.Y.Z origin/main`.
2. Set the version in both places that carry it:
   `npm version X.Y.Z --no-git-tag-version` (updates `package.json` and
   `package-lock.json`) and `VERSION` in `src/version.ts` (reported as
   `adapter_version` on every attestation).
3. `CHANGELOG.md`: move the `[Unreleased]` items under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading with today's date, leave `## [Unreleased]`
   empty above it, and add the two link references at the bottom. For the first
   release, replace `unreleased` in the `0.1.0` heading with the date.
4. Pre-flight locally, exactly what the workflow will check:

   ```bash
   TAG=vX.Y.Z node .github/scripts/release-check.js
   npm ci && npm run check
   npm pack --dry-run   # must list only dist/*, README.md, LICENSE, SECURITY.md and package.json
   ```

5. Open the PR (`chore(release): vX.Y.Z`), let the review pipeline approve it,
   merge.
6. Tag the merge commit on `main`:

   ```bash
   git fetch origin && git switch main && git pull --ff-only
   gh api repos/mitrity-io/mitrity-js/git/ref/tags/vX.Y.Z   # must fail: a tag is never moved
   git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   ```

7. Watch the run under
   <https://github.com/mitrity-io/mitrity-js/actions/workflows/release.yml>;
   approve the `npm` environment when a reviewer is configured.
8. Verify: <https://www.npmjs.com/package/@mitrity/sdk/v/X.Y.Z> shows the
   provenance badge ("Built and signed on GitHub Actions") naming this
   repository and workflow, `npm view @mitrity/sdk@X.Y.Z` resolves, and the
   GitHub Release carries the tarball.

## What the workflow refuses

- A tag whose commit is not on `main`.
- A tag that is not `v` + the `package.json` version, a `src/version.ts` that
  disagrees with `package.json`, or a version without a dated, non-empty
  `CHANGELOG.md` section.
- A failing `npm run check`, or a packed tarball whose version is not the tagged
  one.

## Pre-releases

Tag `v0.2.0-rc.1` with `"version": "0.2.0-rc.1"` (the semver form, which is also
the changelog heading). It is published under the `next` dist-tag, so
`npm install @mitrity/sdk` keeps resolving to the latest final release and
`npm install @mitrity/sdk@next` gets the candidate; the GitHub Release is marked
as a pre-release.

## When a run fails

- `build` failed, or `publish` failed before uploading (for example npm answered
  `E404`/`E403` because a field of the trusted publisher does not match the table
  above): nothing left the repository. Fix the cause and use "Re-run failed jobs";
  if the fix needs a commit, delete the tag (`git push --delete origin vX.Y.Z`)
  and tag again once it is on `main`. This is the only situation in which a tag
  is deleted.
- `publish` succeeded and `release` failed: "Re-run failed jobs". The run's
  artifacts are reused; npm is not touched.
- The version is on npm and is broken: published versions are immutable
  (`npm unpublish` is limited to 72 hours and breaks installs), so
  `npm deprecate @mitrity/sdk@X.Y.Z "<reason>"`, fix forward and release the
  next patch version. Never move a tag that has been published.

## Tooling versions

The workflow pins the actions to commit SHAs; Dependabot bumps them. Node 24 is
used because the npm it bundles supports trusted publishing; the workflow checks
that before publishing.
