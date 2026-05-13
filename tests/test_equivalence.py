from sbom_curator.reconcile.equivalence import licenses_equal, versions_equal

# ----- versions_equal -----


def test_versions_equal_strict_match() -> None:
    assert versions_equal("1.2.3", "1.2.3")


def test_versions_equal_zero_padded_form() -> None:
    assert versions_equal("1.0", "1.0.0")
    assert versions_equal("1.0.0", "1.0.0.0")


def test_versions_equal_local_segment_distinguishes() -> None:
    assert not versions_equal("1.0.0", "1.0.0+abc")
    assert versions_equal("1.0.0+abc", "1.0.0+abc")


def test_versions_equal_real_disagreement() -> None:
    assert not versions_equal("2.0.0", "2.12.5")


def test_versions_equal_falls_back_to_strict_on_parse_failure() -> None:
    # Both unparseable but identical → cheap-path string equality wins.
    assert versions_equal("weird-tag", "weird-tag")
    # Unparseable mismatch → strict says different.
    assert not versions_equal("weird-tag-a", "weird-tag-b")
    # One parseable, one not → also different.
    assert not versions_equal("1.0.0", "weird-tag")


def test_versions_equal_pre_release_ordering() -> None:
    # PEP 440 treats these as different releases.
    assert not versions_equal("1.0.0", "1.0.0a1")
    assert versions_equal("1.0.0a1", "1.0.0a1")


def test_versions_equal_nuget_semver_matches_dotnet_assembly_revision() -> None:
    # `Reactive 4.4.1` (NuGet) paired with `System.Reactive 4.4.1.57983`
    # (assembly version of the same release) -- equal, not a bump.
    assert versions_equal("4.4.1", "4.4.1.57983")
    assert versions_equal("4.4.1.57983", "4.4.1")


def test_versions_equal_rejects_assembly_revision_with_different_patch() -> None:
    # The rule fires only when the first three components match exactly,
    # so a real patch difference is still surfaced.
    assert not versions_equal("4.4.1", "4.4.2.57983")
    assert not versions_equal("1.0.0", "1.0.5.0")


def test_versions_equal_rejects_other_length_pairs() -> None:
    # The (3, 4) length pair is the .NET shared-framework convention.
    # Other length pairs (e.g. (2, 3) or (4, 5)) are NOT eligible -- `1.0`
    # vs `1.0.5` is a real bump, not an assembly revision.
    assert not versions_equal("1.0", "1.0.5")
    assert not versions_equal("1.0.0.1", "1.0.0.1.1")


# ----- licenses_equal -----


def test_licenses_equal_strict_match() -> None:
    assert licenses_equal("MIT", "MIT")


def test_licenses_equal_both_none() -> None:
    assert licenses_equal(None, None)


def test_licenses_equal_one_none_one_set() -> None:
    assert not licenses_equal(None, "MIT")
    assert not licenses_equal("MIT", None)


def test_licenses_equal_or_commutative() -> None:
    assert licenses_equal("Apache-2.0 OR MIT", "MIT OR Apache-2.0")


def test_licenses_equal_and_commutative() -> None:
    assert licenses_equal("Apache-2.0 AND MIT", "MIT AND Apache-2.0")


def test_licenses_equal_real_disagreement() -> None:
    assert not licenses_equal("Apache-2.0", "MIT")


def test_licenses_equal_falls_back_to_strict_on_parse_failure() -> None:
    # license_expression is permissive — most strings parse as
    # LicenseSymbol, including weird ones. Identical garbage still
    # compares equal via the cheap path.
    assert licenses_equal("not a real license", "not a real license")

    # Malformed expressions (unbalanced parens, dangling OR) raise
    # ExpressionError; we fall back to strict string equality, which says
    # different strings differ.
    assert not licenses_equal("MIT OR", "Apache-2.0")
    assert not licenses_equal("(MIT", "MIT")
