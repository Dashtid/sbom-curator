# Workflow: using sbom-overlay on real SBOMs

End-to-end guide for reconciling a hand-curated SPDX SBOM against a
Syft-generated one. Companion to [ARCHITECTURE.md](ARCHITECTURE.md),
which describes how the tool is built; this file describes how to
use it.

## Working directory

The repo's convention is to keep working SBOMs under `artifacts/` at
the repo root, organized by function:

```
artifacts/
├── manual/      hand-curated SPDX SBOMs you author
├── syft/        Syft-generated SPDX SBOMs you scan
└── reports/     reconciliation reports the tool writes
```

`artifacts/` is fully git-ignored, so the SBOMs you drop there stay
local — important when they describe customer-confidential products.
On a fresh clone, create the structure once:

```bash
mkdir -p artifacts/{manual,syft,reports}
```

The structure isn't enforced — sbom-overlay accepts any path through
its `--manual`, `--syft`, and `--output-dir` flags. The convention is
just what makes the workflow legible.

## Naming convention

The same `<name>` ties the three files together. Pick something
descriptive (product + version is the obvious choice):

| Stage | Path | Example |
| --- | --- | --- |
| Manual SBOM you write | `manual/<name>.spdx` | `manual/affinity-6.0.0.spdx` |
| Syft SBOM you generate | `syft/<name>.syft.spdx.json` | `syft/affinity-6.0.0.syft.spdx.json` |
| Reconciliation report | `reports/<name>-overlay.md` | `reports/affinity-6.0.0-overlay.md` |

The `.syft.` infix marks the source so a future Trivy or Tern scan
(`<name>.trivy.spdx.json`) doesn't collide with the Syft one. The
`--name` CLI flag is the join key; the tool builds the report
filename from it automatically.

## End-to-end workflow

### 1. Hand-curate the manual SBOM

Open `artifacts/manual/<name>.spdx` in a text editor and write SPDX
2.3 tag-value content.

**Aim:** the smallest manual SBOM that still misses nothing. Cover
only what a scanner can't see — vendored binaries, statically linked
libraries, runtime-loaded plugins, proprietary natives, system
runtimes installed out-of-band. **Do not re-list what Syft already
finds.** That's wasted curator effort and adds report noise without
adding signal.

A healthy reconciliation has:

- A **small "Only in manual"** bucket — the things you added because
  Syft can't see them.
- A **large "Only in Syft"** bucket — the things Syft found that you
  correctly didn't need to list.
- A **sparse "in both"** bucket — usually coincidental name
  collisions, not deliberate duplication.

If "in both" is large, you're double-listing. Slim the manual.

Watch out for `PackageVersion: NOASSERTION` — that value is
spec-forbidden by SPDX 2.3 §7.3. Omit the field entirely when the
version is unknown.

The repo's existing dogfood fixture
([`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx`](../tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx))
intentionally lists redundant entries to exercise every reconciler
bucket — it's a tool test, not an example of the curator philosophy.
Use the philosophy described above when writing your own SBOMs.

### 2. Generate the Syft SBOM

Run Syft against the actual product install or build directory. Emit
SPDX-JSON (not native Syft JSON or CycloneDX — sbom-overlay only
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
sbom-overlay reconcile \
    --manual artifacts/manual/<name>.spdx \
    --syft   artifacts/syft/<name>.syft.spdx.json \
    --name   <name> \
    --output-dir artifacts/reports
```

The report lands at `artifacts/reports/<name>-overlay.md`. Read it,
file action items based on the four buckets (only-in-manual,
only-in-syft, version disagreements, license disagreements).

## Worked example

Concretely, for Affinity 6.0.0:

```bash
# Step 1: write artifacts/manual/affinity-6.0.0.spdx by hand

# Step 2: generate the Syft side
syft scan dir:'C:/Program Files/Hermes/Affinity' \
  -o spdx-json=artifacts/syft/affinity-6.0.0.syft.spdx.json \
  --source-name affinity --source-version 6.0.0

# Step 3: reconcile
sbom-overlay reconcile \
    --manual artifacts/manual/affinity-6.0.0.spdx \
    --syft   artifacts/syft/affinity-6.0.0.syft.spdx.json \
    --name   affinity-6.0.0 \
    --output-dir artifacts/reports

# Read artifacts/reports/affinity-6.0.0-overlay.md
```
