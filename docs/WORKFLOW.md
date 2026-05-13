# Workflow: using sbom-curator on real SBOMs

End-to-end guide for the curator's loop: maintain one SPDX SBOM by hand,
and use periodic scans to see what changed so you can keep it current.
Companion to [ARCHITECTURE.md](ARCHITECTURE.md), which describes how the
tool is built; this file describes how to use it.

## Curator philosophy

**The manual SBOM is the deliverable.** It is what your regulator (FDA, in
the medical-device case) receives, signs, and audits against. You decide
its **scope** — a focused list of the significant third-party components,
or the full deployed dependency closure, or something in between. The tool
doesn't enforce a scope; whatever your submission calls for, you maintain
the SBOM at that level and the tool reports the per-scan delta against it.

**A scan is input, not a separate artifact.** Each release, scan the
build, see what the scan adds / bumps / no longer shows, decide what to
merge. The tool makes that delta legible.

Two anti-patterns to avoid:

- *Split the deliverable.* Listing only the vendored/static entries in the
  manual and treating the scanner's output as an "auto-generated
  supplement" means you're shipping two artifacts, not one — a regulator
  wants a single SBOM. (A *focused* single SBOM is fine; a *split* one
  isn't.)
- *Hand-rewrite every release.* Maintaining the manual from scratch each
  time is brittle. Periodic scans make drift visible without taking the
  curator's pen out of their hand.

## Working directory

The repo's convention is to keep working SBOMs under `artifacts/` at the
repo root, organized by function:

```
artifacts/
├── manual/      your hand-maintained SPDX SBOMs (the deliverable)
├── syft/        SPDX-JSON scans, one per release
└── reports/     change reports and reconcile reports the tool writes
```

`artifacts/` is fully git-ignored, so the SBOMs you drop there stay
local — important when they describe customer-confidential products.
On a fresh clone, create the structure once:

```bash
mkdir -p artifacts/{manual,syft,reports}
```

The structure isn't enforced — sbom-curator accepts any path through
its `--manual`, `--syft`, and `--output-dir` flags. The convention is
just what makes the workflow legible.

## Naming convention

The same `<name>` ties the files together. Pick something descriptive
(product + version is the obvious choice):

| Stage | Path | Example |
| --- | --- | --- |
| Manual SBOM you maintain | `manual/<name>.spdx` | `manual/affinity-6.0.0.spdx` |
| Scan SBOM (SPDX JSON) | `syft/<name>.syft.spdx.json` | `syft/affinity-6.0.0.syft.spdx.json` |
| Change report (`ingest`) | `reports/<name>-ingest.md` | `reports/affinity-6.0.0-ingest.md` |
| Reconcile report | `reports/<name>-reconcile.md` | `reports/affinity-6.0.0-reconcile.md` |

The `.syft.` infix marks the source so a future Trivy or Tern scan
(`<name>.trivy.spdx.json`) doesn't collide with the Syft one. The
`--name` CLI flag is the join key; the tool builds the report
filename from it automatically.

## End-to-end workflow

### 1. Maintain the manual SBOM

Open `artifacts/manual/<name>.spdx` in a text editor and write SPDX
2.3 tag-value content, at whatever granularity your submission scope
calls for. Typical contents:

- The product itself (root package, declared via `Relationship: ...
  DESCRIBES ...`).
- The third-party components in scope — direct dependencies (PyPI / NuGet
  / system libs), and as much of the transitive closure as your scope
  requires.
- Components a scanner cannot see: vendored binaries, statically linked
  libraries, runtime-loaded plugins, proprietary natives, system runtimes
  installed out-of-band.

You don't write all of that from scratch every release — that's what the
scan input is for. On the first release, seed the manual from a scan plus
your knowledge of what the scanner missed. On subsequent releases, the
change report tells you what moved; you merge the real changes by hand.

**Preflight your manual SBOM** before running the full pipeline:

```bash
sbom-curator lint artifacts/manual/<name>.spdx
```

This translates spdx-tools' opaque grammar errors into line-numbered
actionable messages (notably `PackageVersion: NOASSERTION`, which is
spec-forbidden by SPDX 2.3 §7.3 and blocks parsing — the field is
optional, omit the line entirely when a version is unknown) and warns
on packages `ingest`/`reconcile` would silently skip (`UNKNOWN`
versions, backslash-path names). Exit 0 if clean, 2 on any error.

### 2. Generate the scan SBOM

Run Syft against the **deployed product** — the install directory you
actually ship — not a build/source tree (scanning a build tree pulls in
every tool binary inside vendored source distributions and your own
intermediate artifacts, which floods the *added* bucket with noise). Emit
**SPDX JSON**:

```bash
syft scan dir:/path/to/installed/product \
  -o spdx-json=artifacts/syft/<name>.syft.spdx.json \
  --source-name <product-name> \
  --source-version <product-version>
```

If your existing pipeline emits CycloneDX (or anything else), convert it:

```bash
syft convert your-scan.json -o spdx-json=artifacts/syft/<name>.syft.spdx.json
```

`--syft` only accepts SPDX — there's no in-tree translation layer.

### 3. Ingest — the change report

```bash
sbom-curator ingest \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

A directory scan of a multi-assembly app (notably .NET) gets two kinds of
cleanup on the `--syft` side before the diff:

- **Automatic.** Loose binaries inside vendored source trees (a name that's
  a filesystem path, version `UNKNOWN`) are dropped — they're not packages.
  A package the scan lists more than once is collapsed to one entry: exact
  duplicates (Syft emits a row per referencing project), and "same package
  at different precision" pairs — a NuGet semver `9.0.0` alongside its .NET
  assembly version `9.0.24.52809`, or a version with a `+build` local
  segment alongside the same version without. A genuine multi-version
  install (`foo 1.x` *and* `foo 2.x`) is kept. The run prints how many it
  dropped; `-v` logs each collapse.
- **`--product-prefix`.** Drops the product's own DLLs by name prefix —
  e.g. `--product-prefix Hermes.` for an app whose assemblies are all
  `Hermes.*`. Repeatable, case-insensitive; also useful for framework
  noise you deliberately don't enumerate (`--product-prefix System.
  --product-prefix Microsoft.Extensions.`). (The DESCRIBES-based filter
  already removes the product when the scan names it explicitly; this is
  the fallback for directory scans, where the DESCRIBES target is a
  synthetic directory node that shares no name with the assemblies.)

The report lands at `artifacts/reports/<name>-ingest.md` with four
sections:

- **Added.** In the scan, not in your SBOM. Candidates to add. Some will
  be dev/test/build tooling that doesn't ship — leave it out, or note in
  the SBOM why it's excluded so the next ingest doesn't re-surface the
  question. The rest belong in the SBOM.
- **Bumped.** In both, at different versions. Usually the scan side is the
  truth (it scanned the shipped build); update your entry. The row flags
  whether the license also changed.
- **Only in your SBOM.** The scan matched nothing — neither by PURL, by name,
  nor by family coverage. Three possibilities: (a) the scanner can't see it
  (vendored / statically linked — fine, leave it), (b) the scan lists it
  under a different name — add the canonical PURL to your entry to bridge a
  rename, or for a coarse entry covering many fine-grained scan packages,
  declare it: `PackageComment: <text>sbom-curator covers-prefix:
  Vortice.</text>` makes a `Vortice` entry absorb every `Vortice.*` in the
  scan, or (c) it's genuinely gone (then remove it).
- **Covered by a family entry.** Scan packages absorbed by one of your
  entries' `covers-prefix` declarations — not in *added* because you've
  already declared coverage. Each absorbed package is listed with its
  version so versions are still auditable, but the section is informational
  (no automatic version checks against the umbrella entry — version schemes
  often differ between the umbrella and its sub-packages).
- **Suggested annotations.** When *added* contains a tight name cluster
  (≥3 scan packages sharing a dotted prefix) that no manual entry
  covers, the report proposes the exact `covers-prefix:` annotation that
  would absorb them. The curator decides whether one of their entries
  should own that family; nothing is auto-applied.

To gate CI on findings, pass `--fail-on=BUCKETS`:

```bash
# Fail the build if the scan adds anything or bumps a version.
sbom-curator ingest ... --fail-on added,bumped
```

Valid buckets for `ingest`: `added`, `bumped`, `review`, `license`. For
`reconcile`: `only-in-syft`, `only-in-manual`, `version`, `license`.
Default exit codes: 0 success, 1 gate hit, 2 parse failure.
- **License changed (otherwise unchanged).** Entries that match on name
  and version but whose license string differs from the scan. Reconcile
  against upstream and fix the side that's wrong. (Only listed when *both*
  sides carry a license and they differ — "you say MIT, the scan says
  nothing" isn't a finding.)

Unchanged-and-unchanged entries are counted in the summary but not listed,
so the actionable sections stand out.

Read the report, apply the changes you accept, edit
`artifacts/manual/<name>.spdx` directly. `ingest` does not rewrite the
SBOM — that's deliberate; an `ingest --apply` mode may land later but the
curator's pen stays in their hand by default. Editing by hand keeps your
formatting, comments, package groupings, and curated relationships.

### 4. (optional) Reconcile — the raw diff

For the underlying four-bucket diff without the action relabelling —
handy as a cross-check:

```bash
sbom-curator reconcile \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

Writes `artifacts/reports/<name>-reconcile.md` with the buckets
only-in-manual, only-in-Syft, version disagreements, license
disagreements. `ingest` is built on the same matcher, so the two reports
never disagree about the underlying facts.

## Worked example

Concretely, for Affinity 6.0.0:

```bash
# Step 1: maintain artifacts/manual/affinity-6.0.0.spdx by hand

# Step 2: scan the deployed install, emitting SPDX JSON
syft scan dir:'C:/Program Files/Hermes/Affinity' \
  -o spdx-json=artifacts/syft/affinity-6.0.0.syft.spdx.json \
  --source-name affinity --source-version 6.0.0
# (if your pipeline produces CycloneDX instead:
#  syft convert affinity.cdx.json -o spdx-json=artifacts/syft/affinity-6.0.0.syft.spdx.json)

# Step 3: change report (Affinity's assemblies are all Hermes.* — drop them)
sbom-curator ingest \
    --manual artifacts/manual/affinity-6.0.0.spdx \
    --syft   artifacts/syft/affinity-6.0.0.syft.spdx.json \
    --name   affinity-6.0.0 \
    --product-prefix Hermes. \
    --output-dir artifacts/reports

# Read artifacts/reports/affinity-6.0.0-ingest.md; apply the added/bumped
# entries you accept to artifacts/manual/affinity-6.0.0.spdx by hand.
```
