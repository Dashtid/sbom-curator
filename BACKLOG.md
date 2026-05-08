# Backlog

Open work for sbom-curator. Each item names a **trigger** — the real-world
signal that justifies starting it. Nothing here is urgent; items wait for
their trigger so the codebase stays free of speculative complexity.

## Open

### Affinity-shaped fixture + .NET name-style normalization

**Trigger:** an anonymizable Affinity SBOM (or any real .NET SBOM) at
**the same product version** as the matching Syft scan is available to
commit as a fixture.

The dicom-fuzzer fixture covers the Python case. .NET surfaces a new
shape of false-positive disagreement that lowercase-name match cannot
bridge. Concrete cases captured from a real run of v5 manual against v6
Syft (different versions, but the naming-style mismatch is the same):

| Manual lists | Syft sees | Mismatch type |
| --- | --- | --- |
| `Reactive` 4.4.1 | `System.Reactive` 6.1.0 (and `.Core`, `.Interfaces`) | Vendor-prefix dropped in manual |
| `Vortice` 3.2.0 | `Vortice.DXGI`, `.Direct2D1`, `.Direct3D11` (×12) | Manual lists umbrella; Syft lists individual NuGet packages |
| `CommunityToolkit` 8.2.2 | `CommunityToolkit.Mvvm`, `.Common`, `.HighPerformance`, `.WinUI.*` (×35) | Same umbrella-vs-package pattern |
| `CUDA Runtime Library` 11.0.194 | `NVIDIA CUDA 11.0.194 Runtime` 6,14,11,11000 | Different name string + Syft picked up Windows file-version metadata literally |

Two separate normalization questions surface:

1. **Splitting** — does manual `CommunityToolkit` represent the umbrella
   (matches all sub-packages) or specifically `CommunityToolkit.Mvvm`?
   The right answer is curator's intent — the tool can't infer it
   without a hint, so the manual SBOM author may need to be more
   specific or a curator-side annotation may be needed.
2. **Prefixing** — `Reactive` → `System.Reactive` is a clean
   vendor-prefix strip on the manual side. `CommunityToolkit` →
   `CommunityToolkit.Mvvm` is a sibling-suffix add. Different rules,
   handle separately.

**v5-manual-vs-v6-Syft is the wrong pair to design against** — the
products diverge between versions. What's needed is a v6 manual SBOM
matching the v6 Syft scan; design starts when that pair exists.

### Manual SBOM linter / preflight

**Trigger:** repeated friction landing real customer SBOMs on the
parser. Already observed: the v5 Affinity manual SBOM had a
spec-violating `PackageVersion: NOASSERTION` line (SPDX 2.3 §7.3
forbids that value; the field is optional, so absence is the right way
to express "unknown"). spdx-tools rejects it correctly but the error
message is opaque.

A small `sbom-curator lint manual.spdx` subcommand would catch known
spec violations before the reconcile step, with actionable messages
("delete the PackageVersion line — the value `NOASSERTION` is not
permitted; absence means unknown"). Defers the linting story to its
own command rather than making the parser permissive.

### Per-file vs aggregated artifact deduplication

**Trigger:** a Syft scan produces visibly duplicate "Only in Syft"
entries that distract the reviewer from real findings.

Observed in the Affinity v6 scan: `CommunityToolkit.Mvvm 8.2.1` and
`CommunityToolkit.Mvvm 8.2.1.1+2258fd3103` appear as separate rows
because PEP 440 treats local segments as distinguishing (correctly per
spec, but the two entries are the same package observed at different
file-system locations within the same install).

Possible approach: in `Reconciliation`, collapse entries that share a
PURL up to the local segment, before the `only_in_syft` list is
finalized. Need real cases to validate the rule doesn't hide actual
multi-version installs.

### CycloneDX support

**Trigger:** a real workflow needs to consume CycloneDX. Today
sbom-sentinel produces CycloneDX for Grype and that pipeline is
unaffected by us; sbom-curator is SPDX-on-SPDX by design.

If triggered, add `sbom_curator/parsers/cyclonedx.py` mirroring the
spdx parser shape. The `Component` model is format-agnostic so the
reconciler and reporter need no changes.

### Snapshot tests for the Markdown report

**Trigger:** a layout change accidentally breaks the "stable diff
run-to-run" promise — or earlier, if pinning shape becomes desirable.

`tests/test_report.py` exercises individual rendering primitives. Add a
snapshot test that pins the full rendered report against the dogfood
fixture, so layout regressions (column reordering, section omission,
heading rename) fail CI rather than slipping through.

### Configurable exit-code thresholds

**Trigger:** someone wants to gate CI on reconciliation findings.

Add a `--fail-on=version,license,only-in-syft` flag that maps to a
non-zero exit when any selected bucket is non-empty. The
`Reconciliation` dataclass already exposes the inputs (`version_mismatches`,
`license_mismatches`, etc.). Default stays exit-0 — the artifact is the
report; gating is opt-in.

### CHANGELOG and 0.1.0 tag

**Trigger:** ready to cut a public release.

Add `CHANGELOG.md` (Keep-a-Changelog format), bump `pyproject.toml` to
`0.1.0`, tag the release commit, push the tag. Optionally publish to
PyPI when the tool's audience extends past the local toolchain.

## Done

Recorded for context; remove entries once the project context fully
covers them.

| Shipped in | What |
| --- | --- |
| PR #1 | SPDX 2.3 JSON parser (hand-rolled) |
| PR #2 | Switch parser to spdx-tools (gains tag-value, YAML, RDF) |
| PR #3 | Drop CycloneDX from v1 scope |
| PR #4 | dicom-fuzzer 1.11.0 dogfood fixture pair |
| PR #5 | Reconciler + Markdown report + CLI wiring |
| PR #6 | README running example + `[i]` marker escape fix |
| PR #7 | Loose version (PEP 440) + license (SPDX expression) equivalence |
| PR #9 | Content-sniff SPDX tag-value under `.txt` extension (real customer SBOMs commonly land as `.txt`) |
