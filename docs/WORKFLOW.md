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

**If `ingest` ever fails to parse your SBOM**, run `sbom-curator lint
artifacts/manual/<name>.spdx`. It translates the one spdx-tools error
the curator is likely to hit (`PackageVersion: NOASSERTION`, spec-
forbidden by SPDX 2.3 §7.3) into a line-numbered actionable message,
and flags the cases where `ingest` will silently skip a package
(`UNKNOWN` versions, backslash-path names). It does not flag a missing
`PackageVersion` line, because that is an explicit curator choice per
spec ("absence means unknown") and the entry stays in your SBOM
regardless — only the cross-scan comparison skips it.

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

The report lands at `artifacts/reports/<name>-ingest.md`. Read the four
actionable sections and edit your manual SBOM by hand:

- **Added.** In the scan, not in your SBOM. Most of these are dev/test
  tooling or framework packages that ship with the runtime — leave them
  out. Anything you genuinely want to track gets a new entry in the
  manual.
- **Bumped.** In both, at different versions. Update the manual's
  `PackageVersion` line if the scan's version is what shipped.
- **Only in your SBOM.** The scan didn't find a match. Usually fine —
  these are the vendored / statically-linked / system-installed
  components Syft can't see (the whole reason a manual SBOM exists).
- **License changed (otherwise unchanged).** Same name and version, the
  license string disagrees. Reconcile against upstream and fix the side
  that's wrong.

Unchanged entries are counted in the summary but not listed, so the
actionable sections stand out. Two informational sections may also
appear: **Covered by a family entry** (scan packages absorbed by a
`covers-prefix:` annotation — see "Optional knobs" below) and
**Suggested annotations** (tight name clusters in *added* that you
could declare coverage for).

`ingest` does not rewrite your SBOM. Editing by hand keeps your
formatting, comments, package groupings, and curated relationships —
which is what the regulator sees and audits.

#### Folder-scan mode (multiple products at once)

Once you're maintaining two or more SBOMs that follow the convention
above, the explicit-flags form gets repetitive. `ingest` accepts a
positional folder path instead:

```bash
sbom-curator ingest artifacts/
```

It discovers every `<name>.spdx` in `artifacts/manual/` that has a
matching `<name>.syft.spdx.json` in `artifacts/syft/`, runs the per-pair
pipeline for each, and writes one report per pair to
`artifacts/reports/<name>-ingest.md`.

One-line console summary per pair plus a footer with processed / gate /
parse-error counts. Exit code is the worst outcome across pairs (2 for
parse failure, 1 for any `--fail-on` gate hit, 0 clean). Per-pair parse
failures don't abort the run — the report still gets written for the
pairs that parsed.

The positional path is mutually exclusive with `--manual` / `--syft` /
`--name`; pick one mode. Global flags (`--product-prefix`, `--fail-on`)
apply to every pair.

Loose-by-default extension matching tolerates non-canonical scan
filenames (`.sbom.spdx.json`, `.spdx.json`) and dotted-vs-dashed version
segments. For CI runs that should enforce the convention strictly, pass
`--strict-naming` — that requires `.syft.spdx.json` exactly. Files in
`manual/` and `syft/` that have a counterpart only on one side are
reported as orphans; files that don't match any expected extension are
silently skipped.

A real-world curator filename like `P60-199-01 SBOM Affinity 6.0.0.spdx`
will not auto-pair with `affinity.6.0.0.72.sbom.spdx.json` — the stems
are too different. Either rename to the convention
(`affinity-6.0.0.spdx` + `affinity-6.0.0.syft.spdx.json`) or fall back
to the explicit-flags form for that pair.

#### Optional knobs (skip until the basic report is too noisy)

A first run on a real product can produce a long *added* section, much
of it noise (the product's own DLLs decomposed into assemblies, .NET
framework packages, …). Three optional levers, in order of typical
payoff:

- **`--product-prefix PREFIX`** drops scan packages whose name starts
  with PREFIX. Use it for the product's own assemblies (an app whose
  DLLs are all `Hermes.*` → `--product-prefix Hermes`) or for framework
  noise you don't enumerate (`--product-prefix System.
  --product-prefix Microsoft.Extensions.`). Repeatable.
- **A canonical PURL on a manual entry** bridges a rename. If you list
  `Reactive` but the scan calls it `System.Reactive`, add
  `ExternalRef: PACKAGE-MANAGER purl pkg:nuget/System.Reactive@4.4.1`
  to your `Reactive` entry. The matcher pairs them on PURL.
- **`PackageComment: <text>sbom-curator covers-prefix: PREFIX</text>`**
  on a manual entry absorbs every scan package whose name starts with
  PREFIX into that entry. Useful when you list a family coarsely
  (`Vortice 3.2.0`) and the scan lists every sub-package
  (`Vortice.DXGI`, `Vortice.Direct3D11`, …). The umbrella entry is not
  consumed; one entry can cover many sub-packages.

The report's **Suggested annotations** section proposes `covers-prefix:`
lines when it spots clusters worth declaring; copy/paste if it makes
sense, ignore otherwise.

To gate CI on findings, pass `--fail-on=BUCKETS`:

```bash
sbom-curator ingest ... --fail-on added,bumped
```

Valid buckets for `ingest`: `added`, `bumped`, `review`, `license`. For
`reconcile`: `only-in-syft`, `only-in-manual`, `version`, `license`.
Exit codes: 0 success, 1 gate hit, 2 parse failure.

Automatic cleanup happens every run regardless: scan rows with no
usable version (literal `UNKNOWN`, missing) and rows whose name is a
filesystem path are dropped (they're loose binaries, not packages),
and duplicate scan entries (Syft emitting one row per referencing
project, or a NuGet semver alongside its .NET assembly version) are
collapsed to one.

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
