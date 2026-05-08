# Workflow: using sbom-curator on real SBOMs

End-to-end guide for the curator's loop: maintain one authoritative SPDX
SBOM (the FDA submission deliverable), and use Syft scans as periodic
input to keep it current. Companion to [ARCHITECTURE.md](ARCHITECTURE.md),
which describes how the tool is built; this file describes how to use it.

## Curator philosophy

**The manual SBOM is the deliverable.** It is what your regulator (FDA, in
the medical-device case) receives, signs, and audits against. It must meet
the [NTIA minimum baseline](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf):
author, timestamp, supplier, component name, version, hash (where
practical), unique identifier, dependency relationship — for every shipped
component, including ones a scanner cannot see.

**Syft is input, not a separate artifact.** Each release, scan the build,
diff the scan against the manual SBOM, decide what to merge. The tool
makes that diff legible.

This contrasts with two anti-patterns:

- *Slim manual + ship the union.* Listing only vendored/static entries in
  the manual and treating Syft's output as an "auto-generated supplement"
  fails NTIA review: the deliverable is one SBOM, and that SBOM has to be
  comprehensive on its own.
- *Hand-rewrite every release.* Maintaining the manual from scratch is
  brittle. Periodic Syft input makes drift visible without taking the
  curator's pen out of their hand.

## Working directory

The repo's convention is to keep working SBOMs under `artifacts/` at the
repo root, organized by function:

```
artifacts/
├── manual/      hand-curated SPDX SBOMs you author (the deliverable)
├── syft/        Syft-generated SPDX SBOMs from each release scan
└── reports/     reconciliation reports the tool writes
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

The same `<name>` ties the three files together. Pick something
descriptive (product + version is the obvious choice):

| Stage | Path | Example |
| --- | --- | --- |
| Manual SBOM you maintain | `manual/<name>.spdx` | `manual/affinity-6.0.0.spdx` |
| Syft SBOM you generate | `syft/<name>.syft.spdx.json` | `syft/affinity-6.0.0.syft.spdx.json` |
| Reconciliation report | `reports/<name>-reconcile.md` | `reports/affinity-6.0.0-reconcile.md` |

The `.syft.` infix marks the source so a future Trivy or Tern scan
(`<name>.trivy.spdx.json`) doesn't collide with the Syft one. The
`--name` CLI flag is the join key; the tool builds the report
filename from it automatically.

## End-to-end workflow

### 1. Maintain the manual SBOM

Open `artifacts/manual/<name>.spdx` in a text editor and write SPDX
2.3 tag-value content. The aim is **comprehensive enough to meet
NTIA baseline on its own** — that means every component shipped:

- The product itself (root package, declared via `Relationship: ...
  DESCRIBES ...`).
- Direct dependencies (PyPI packages, NuGet packages, system libs,
  whatever the platform's package manifest declares).
- Transitive dependencies that ship in the released artifact.
- Components a scanner cannot see: vendored binaries, statically
  linked libraries, runtime-loaded plugins, proprietary natives,
  system runtimes installed out-of-band.

You don't write all of that from scratch every release — that's what
the Syft input is for. On the first release, seed the manual from a
Syft scan plus your knowledge of what Syft missed. On subsequent
releases, the reconcile report tells you what changed; you merge the
real changes by hand.

Watch out for `PackageVersion: NOASSERTION` — that value is
spec-forbidden by SPDX 2.3 §7.3. Omit the field entirely when the
version is unknown.

### 2. Generate the Syft SBOM

Run Syft against the actual product install or build directory. Emit
SPDX-JSON (not native Syft JSON or CycloneDX — sbom-curator only
parses SPDX):

```bash
syft scan dir:/path/to/product \
  -o spdx-json=artifacts/syft/<name>.syft.spdx.json \
  --source-name <product-name> \
  --source-version <product-version>
```

If you already have a native Syft JSON file, convert it with
`syft convert <file> -o spdx-json=artifacts/syft/<name>.syft.spdx.json`
instead of re-scanning.

### 3. Reconcile

```bash
sbom-curator reconcile \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

The report lands at `artifacts/reports/<name>-reconcile.md`. Four
buckets:

- **Only in manual.** Components you have that Syft didn't see —
  expected for vendored/static entries. Treat anything else as a hint
  that the entry is stale (the dep was removed) or wrongly named (the
  scanner sees it under a different name; see the .NET notes in
  [`BACKLOG.md`](../BACKLOG.md)).
- **Only in Syft.** Components Syft found that aren't in the manual.
  Each is a candidate to add to the manual SBOM. Some will be true
  build-tooling that doesn't ship and can be ignored; the rest belong
  in the manual.
- **Version disagreements.** Same component, different version on
  each side. Usually the Syft side is the truth (it scanned the
  shipped build); update the manual.
- **License disagreements.** Same component, different license. Often
  a recording error in the manual; reconcile against upstream.

Read the report, decide which deltas land in the manual SBOM, edit
`artifacts/manual/<name>.spdx` directly. The `reconcile` command does
not rewrite the manual — that's deliberate; an `ingest --apply`
command may come later but the curator's pen stays in their hand by
default.

## Worked example

Concretely, for Affinity 6.0.0:

```bash
# Step 1: maintain artifacts/manual/affinity-6.0.0.spdx by hand
#         (or seed it from the first Syft scan + missing vendored entries)

# Step 2: generate the Syft side
syft scan dir:'C:/Program Files/Hermes/Affinity' \
  -o spdx-json=artifacts/syft/affinity-6.0.0.syft.spdx.json \
  --source-name affinity --source-version 6.0.0

# Step 3: reconcile
sbom-curator reconcile \
    --manual artifacts/manual/affinity-6.0.0.spdx \
    --syft   artifacts/syft/affinity-6.0.0.syft.spdx.json \
    --name   affinity-6.0.0 \
    --output-dir artifacts/reports

# Read artifacts/reports/affinity-6.0.0-reconcile.md and merge real
# deltas into artifacts/manual/affinity-6.0.0.spdx by hand.
```
