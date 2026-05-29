# Workflow

End-to-end guide for the curator's loop: maintain one SPDX SBOM by hand, use
periodic scans to surface drift. Companion to
[ARCHITECTURE.md](ARCHITECTURE.md).

## Curator philosophy

The manual SBOM is the deliverable. It is what your regulator (FDA, in the
medical-device case) receives, signs, and audits against. Scope is the
curator's call — a focused list of significant components, the full deployed
closure, or anything in between. The tool reports the per-scan delta against
whatever you chose.

A scan is input, not a parallel artifact. Each release, scan the build, read
what the scan added / bumped / no longer shows, decide what to merge.

Two anti-patterns:

- **Split deliverable.** Listing only vendored entries in the manual and
  treating the scanner's output as an "auto-generated supplement" ships two
  artifacts. A regulator wants one.
- **Hand-rewrite every release.** Brittle. Periodic scans make drift visible
  without taking the curator's pen out of their hand.

## Working directory

```
artifacts/
├── manual/      hand-maintained SBOMs (working copies, with tool annotations)
├── syft/        SPDX-JSON scans, one per release
├── reports/     change reports + reconcile reports the tool writes
└── finalized/   clean copies for delivery (tool annotations stripped)
```

`artifacts/` is git-ignored. Create the structure once:

```bash
mkdir -p artifacts/{manual,syft,reports,finalized}
```

Paths are configurable via `--manual`, `--syft`, and `--output-dir` — the
convention is what makes folder mode (below) work without flags.

## Naming convention

A shared `<name>` ties the files together:

| Stage | Path | Example |
| --- | --- | --- |
| Manual SBOM | `manual/<name>.spdx` | `manual/affinity-6.0.0.spdx` |
| Scan SBOM | `syft/<name>.syft.spdx.json` | `syft/affinity-6.0.0.syft.spdx.json` |
| Change report | `reports/<name>-ingest.md` | `reports/affinity-6.0.0-ingest.md` |
| Reconcile report | `reports/<name>-reconcile.md` | `reports/affinity-6.0.0-reconcile.md` |
| Delivery copy | `finalized/<name>.spdx` | `finalized/affinity-6.0.0.spdx` |

The `.syft.` infix marks the source so a future Trivy or Tern scan
(`<name>.trivy.spdx.json`) won't collide. The `--name` flag is the join key
and becomes the report filename.

## End-to-end workflow

### 1. Maintain the manual SBOM

Open `artifacts/manual/<name>.spdx` and write SPDX 2.3 tag-value content.
Typical contents:

- The product itself (declared via `Relationship: ... DESCRIBES ...`).
- In-scope third-party components: direct dependencies and as much of the
  transitive closure as the submission requires.
- Components a scanner can't see: vendored binaries, statically linked libs,
  runtime-loaded plugins, system runtimes installed out-of-band.

Don't rewrite from scratch every release. On the first release, seed from a
scan plus your knowledge of what the scanner missed. On later releases, the
change report tells you what moved.

If `ingest` fails to parse, run `sbom-curator lint
artifacts/manual/<name>.spdx`. It translates the spdx-tools grammar errors
into line-numbered messages and flags packages `ingest` would silently skip.

### 2. Generate the scan SBOM

Scan the **deployed product** — the install directory you ship, not a build
or source tree. Build trees pull in every tool binary inside vendored source
distributions and flood `added`.

```bash
syft scan dir:/path/to/installed/product \
  -o spdx-json=artifacts/syft/<name>.syft.spdx.json \
  --source-name <product-name> \
  --source-version <product-version>
```

If your pipeline emits CycloneDX:

```bash
syft convert your-scan.json -o spdx-json=artifacts/syft/<name>.syft.spdx.json
```

`--syft` only accepts SPDX.

### 3. Ingest — the change report

```bash
sbom-curator ingest \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

The report lands at `artifacts/reports/<name>-ingest.md`. Four actionable
sections:

- **Added** — in the scan, not in the SBOM. Dev/test tooling and framework
  packages that ship with the runtime: leave them out. Real dependencies:
  add an entry.
- **Bumped** — in both, at different versions. Update `PackageVersion` if
  the scan's version is what shipped.
- **Only in your SBOM** — the scan didn't find a match. Usually vendored or
  statically linked.
- **License changed (otherwise unchanged)** — same name and version, license
  string disagrees. Reconcile against upstream.

Unchanged entries are counted, not enumerated. Two informational sections
may also appear: **Covered by a family entry** (scan packages absorbed by a
`covers-prefix:` annotation) and **Suggested annotations** (clusters worth
declaring coverage for).

`ingest` does not rewrite the SBOM. Editing by hand preserves formatting,
comments, package groupings, and curated relationships.

#### Folder mode

When you maintain two or more SBOMs that follow the convention,
`sbom-curator ingest artifacts/` discovers every pair in `manual/` + `syft/`
and writes one report per pair to `reports/`.

One line per pair plus an aggregate footer (`processed N pair(s); M gate
hit(s); K parse error(s)`). Exit code is the worst across pairs (2 parse
failure, 1 gate hit, 0 clean). Per-pair parse failures don't abort.

Mutually exclusive with `--manual` / `--syft` / `--name`. Global flags
(`--product-prefix`, `--fail-on`) apply to every pair.

Loose-by-default extension matching tolerates `.sbom.spdx.json` and
`.spdx.json`. For CI: `--strict-naming` requires `.syft.spdx.json` exactly.

A curator filename like `P60-199-01 SBOM Affinity 6.0.0.spdx` won't
auto-pair with `affinity.6.0.0.72.sbom.spdx.json` — the stems differ too
much. Rename or fall back to explicit flags.

#### Optional flags

Three levers, in order of typical payoff:

- **`--product-prefix PREFIX`** — drop scan packages whose name starts with
  PREFIX. For the product's own assemblies (e.g. `--product-prefix Hermes.`)
  or framework noise (`--product-prefix System. --product-prefix
  Microsoft.Extensions.`). Repeatable, case-insensitive.
- **Canonical PURL on a manual entry** — bridges a rename. If you list
  `Reactive` but the scan calls it `System.Reactive`, add
  `ExternalRef: PACKAGE-MANAGER purl pkg:nuget/System.Reactive@4.4.1` to the
  `Reactive` entry.
- **`PackageComment: <text>sbom-curator covers-prefix: PREFIX</text>`** — on
  a manual entry, absorbs every unmatched scan package whose name starts
  with PREFIX into that entry. Useful for coarse family entries
  (`Vortice 3.2.0` absorbing `Vortice.DXGI`, `Vortice.Direct3D11`, …). One
  entry can cover many sub-packages.

`--fail-on=BUCKETS` gates CI. Ingest buckets: `added`, `bumped`, `review`,
`license`. Reconcile buckets: `only-in-syft`, `only-in-manual`, `version`,
`license`. Exit codes: 0 clean, 1 gate hit, 2 parse failure.

Automatic per-run cleanup (no flags): scan rows with no usable version
(`UNKNOWN`, missing) or path-like names are dropped; exact duplicates and
NuGet semver ↔ .NET assembly-version pairs are collapsed.

### 4. (optional) Reconcile — the raw diff

```bash
sbom-curator reconcile \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

Writes the four-bucket diff (only-in-manual, only-in-Syft, version
disagreements, license disagreements). `ingest` is built on the same
matcher, so the two reports never disagree about the facts.

### 5. Finalize — strip tool annotations for delivery

The working SBOM in `manual/` accumulates `sbom-curator covers-prefix:` (and
any future `sbom-curator <key>:`) annotations. Strip them before submission:

```bash
sbom-curator finalize artifacts/
```

Reads every `<name>.spdx` in `manual/` and writes a clean copy to
`finalized/<name>.spdx`. A `PackageComment` containing only tool lines is
removed entirely; a mixed block keeps curator notes and loses tool lines.

For a single file:

```bash
sbom-curator finalize \
    --manual artifacts/manual/affinity-6.0.0.spdx \
    --output artifacts/finalized/affinity-6.0.0.spdx
```

Text-level edit — every byte outside the stripped lines is preserved. The
source SBOM is never modified. Tag-value SPDX only.

## Worked example

For Affinity 6.0.0:

```bash
# 1. Maintain artifacts/manual/affinity-6.0.0.spdx by hand.

# 2. Scan the deployed install.
syft scan dir:'C:/Program Files/Hermes/Affinity' \
  -o spdx-json=artifacts/syft/affinity-6.0.0.syft.spdx.json \
  --source-name affinity --source-version 6.0.0

# 3. Change report (drop the product's Hermes.* assemblies).
sbom-curator ingest \
    --manual artifacts/manual/affinity-6.0.0.spdx \
    --syft   artifacts/syft/affinity-6.0.0.syft.spdx.json \
    --name   affinity-6.0.0 \
    --product-prefix Hermes. \
    --output-dir artifacts/reports

# 4. Read the report; apply accepted entries to the manual by hand.

# 5. Strip tool annotations for delivery.
sbom-curator finalize artifacts/
```
