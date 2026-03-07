import pytest

from data.database import Manifest, ManifestBuildDate, ManifestChild, Repository
from data.model.oci.build_date import (
    get_child_manifest_max_build_date,
    get_manifest_build_date,
    has_unprocessed_children,
    set_manifest_build_date,
)
from test.fixtures import *


def _get_first_manifest(initialized_db):
    """Helper to get the first available manifest and its repository."""
    manifest = Manifest.select().first()
    assert manifest is not None
    return manifest


def test_set_and_get_manifest_build_date(initialized_db):
    """set_manifest_build_date creates a row, get_manifest_build_date retrieves it."""
    manifest = _get_first_manifest(initialized_db)

    build_date_ms = 1705315800000
    set_manifest_build_date(manifest.id, manifest.repository_id, build_date_ms)

    result = get_manifest_build_date(manifest.id)
    assert result == build_date_ms


def test_set_manifest_build_date_null(initialized_db):
    """Setting build_date to None stores a NULL value."""
    manifest = _get_first_manifest(initialized_db)

    set_manifest_build_date(manifest.id, manifest.repository_id, None)

    row = ManifestBuildDate.get(ManifestBuildDate.manifest == manifest.id)
    assert row.build_date is None


def test_set_manifest_build_date_idempotent(initialized_db):
    """Calling set_manifest_build_date twice does not raise (IntegrityError caught)."""
    manifest = _get_first_manifest(initialized_db)

    set_manifest_build_date(manifest.id, manifest.repository_id, 1705315800000)
    set_manifest_build_date(manifest.id, manifest.repository_id, 9999999999999)

    result = get_manifest_build_date(manifest.id)
    assert result == 1705315800000


def test_get_manifest_build_date_no_row(initialized_db):
    """Returns None when no ManifestBuildDate row exists."""
    manifest = _get_first_manifest(initialized_db)

    result = get_manifest_build_date(manifest.id)
    assert result is None


def test_get_child_manifest_max_build_date(initialized_db):
    """For a manifest list, returns MAX(build_date) across children."""
    child_entry = ManifestChild.select().first()
    if child_entry is None:
        pytest.skip("No manifest list children in test database")

    parent_id = child_entry.manifest_id
    repo_id = child_entry.repository_id

    children = ManifestChild.select().where(ManifestChild.manifest == parent_id)

    dates = [1000000, 2000000, 3000000]
    for i, child in enumerate(children):
        date = dates[i] if i < len(dates) else dates[-1]
        set_manifest_build_date(child.child_manifest_id, repo_id, date)

    result = get_child_manifest_max_build_date(parent_id, repo_id)
    assert result == max(dates[: min(len(list(children)), len(dates))])


def test_get_child_manifest_max_build_date_no_children(initialized_db):
    """Returns None when there are no child manifests."""
    manifest = _get_first_manifest(initialized_db)
    result = get_child_manifest_max_build_date(manifest.id, manifest.repository_id)
    assert result is None


def _get_manifest_list_with_children(initialized_db):
    """Helper: finds a manifest list parent that has child manifests."""
    child_entry = ManifestChild.select().first()
    if child_entry is None:
        pytest.skip("No manifest list children in test database")
    return child_entry.manifest_id, child_entry.repository_id


def test_has_unprocessed_children_all_unprocessed(initialized_db):
    """Returns True when no child manifests have ManifestBuildDate rows."""
    parent_id, repo_id = _get_manifest_list_with_children(initialized_db)
    assert has_unprocessed_children(parent_id, repo_id) is True


def test_has_unprocessed_children_some_processed(initialized_db):
    """Returns True when at least one child lacks a ManifestBuildDate row."""
    parent_id, repo_id = _get_manifest_list_with_children(initialized_db)

    children = list(ManifestChild.select().where(ManifestChild.manifest == parent_id))
    assert len(children) >= 1

    set_manifest_build_date(children[0].child_manifest_id, repo_id, 1000000)

    if len(children) > 1:
        assert has_unprocessed_children(parent_id, repo_id) is True
    else:
        assert has_unprocessed_children(parent_id, repo_id) is False


def test_has_unprocessed_children_all_processed(initialized_db):
    """Returns False when every child manifest has a ManifestBuildDate row."""
    parent_id, repo_id = _get_manifest_list_with_children(initialized_db)

    children = ManifestChild.select().where(ManifestChild.manifest == parent_id)
    for i, child in enumerate(children):
        set_manifest_build_date(child.child_manifest_id, repo_id, (i + 1) * 1000000)

    assert has_unprocessed_children(parent_id, repo_id) is False


def test_has_unprocessed_children_no_children(initialized_db):
    """Returns False for a manifest that has no children at all."""
    manifest = Manifest.select().first()
    has_children = ManifestChild.select().where(ManifestChild.manifest == manifest.id).exists()
    if has_children:
        manifest = (
            Manifest.select()
            .where(~(Manifest.id << ManifestChild.select(ManifestChild.manifest)))
            .first()
        )
        if manifest is None:
            pytest.skip("All manifests are parents in test database")

    assert has_unprocessed_children(manifest.id, manifest.repository_id) is False


def test_get_child_manifest_max_build_date_partial_backfill(initialized_db):
    """MAX only considers children that have ManifestBuildDate rows;
    children without rows are excluded from the aggregate."""
    parent_id, repo_id = _get_manifest_list_with_children(initialized_db)

    children = list(ManifestChild.select().where(ManifestChild.manifest == parent_id))
    if len(children) < 2:
        pytest.skip("Need at least 2 children to test partial backfill")

    set_manifest_build_date(children[0].child_manifest_id, repo_id, 5000000)

    result = get_child_manifest_max_build_date(parent_id, repo_id)
    assert result == 5000000
