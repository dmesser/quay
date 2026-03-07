import pytest

from data.database import Manifest, ManifestBuildDate, ManifestChild
from data.model.oci.build_date import get_manifest_build_date, set_manifest_build_date
from test.fixtures import *
from workers.manifestbuilddatebackfillworker import (
    _DEFER,
    ManifestBuildDateBackfillWorker,
)


def test_backfill_no_work(initialized_db):
    """When all manifests already have ManifestBuildDate rows, worker returns False."""
    worker = ManifestBuildDateBackfillWorker()

    for manifest in Manifest.select():
        ManifestBuildDate.get_or_create(
            manifest=manifest.id,
            defaults={"repository": manifest.repository_id, "build_date": None},
        )

    assert not worker._backfill_manifest_build_dates()


def test_backfill_basic(initialized_db):
    """Worker populates ManifestBuildDate for manifests without a row."""
    worker = ManifestBuildDateBackfillWorker()

    assert ManifestBuildDate.select().count() == 0

    assert worker._backfill_manifest_build_dates()

    manifest_count = Manifest.select().count()
    build_date_count = ManifestBuildDate.select().count()
    assert build_date_count > 0
    assert build_date_count <= manifest_count

    for mbd in ManifestBuildDate.select():
        assert mbd.manifest_id is not None
        assert mbd.repository_id is not None


def test_backfill_idempotent(initialized_db):
    """Running backfill multiple times does not create duplicate rows."""
    worker = ManifestBuildDateBackfillWorker()

    worker._backfill_manifest_build_dates()
    first_count = ManifestBuildDate.select().count()

    worker._backfill_manifest_build_dates()
    second_count = ManifestBuildDate.select().count()

    assert first_count == second_count


def test_backfill_completes(initialized_db):
    """After backfill runs to completion, worker returns False (no remaining work)."""
    worker = ManifestBuildDateBackfillWorker()

    while worker._backfill_manifest_build_dates():
        pass

    assert not worker._backfill_manifest_build_dates()


def _get_manifest_list_parent(initialized_db):
    """Helper: returns a (parent_manifest, [child_manifests]) from the test DB."""
    child_entry = ManifestChild.select().first()
    if child_entry is None:
        pytest.skip("No manifest list children in test database")

    parent = Manifest.get_by_id(child_entry.manifest_id)
    children = list(ManifestChild.select().where(ManifestChild.manifest == parent.id))
    return parent, children


def test_extract_build_date_defers_when_children_not_backfilled(initialized_db):
    """_extract_build_date returns _DEFER for a manifest list whose
    children have not been backfilled yet, preventing a premature NULL row."""
    worker = ManifestBuildDateBackfillWorker()
    parent, children = _get_manifest_list_parent(initialized_db)

    assert len(children) > 0
    assert (
        not ManifestBuildDate.select()
        .where(ManifestBuildDate.manifest << [c.child_manifest_id for c in children])
        .exists()
    )

    result = worker._extract_build_date(parent)
    assert result is _DEFER


def test_extract_build_date_proceeds_after_children_backfilled(initialized_db):
    """_extract_build_date returns a date (not _DEFER) for a manifest list
    once all children have been backfilled."""
    worker = ManifestBuildDateBackfillWorker()
    parent, children = _get_manifest_list_parent(initialized_db)

    for i, child in enumerate(children):
        set_manifest_build_date(child.child_manifest_id, child.repository_id, (i + 1) * 1000000)

    result = worker._extract_build_date(parent)
    assert result is not _DEFER
    expected_max = max((i + 1) * 1000000 for i in range(len(children)))
    assert result == expected_max


def test_backfill_manifest_list_not_finalized_before_children(initialized_db):
    """Integration test: when the backfill worker processes a manifest list
    before its children, the manifest list must NOT get a ManifestBuildDate
    row (i.e. it is deferred). After children are backfilled and the worker
    runs again, the manifest list gets the correct MAX(child build dates)."""
    worker = ManifestBuildDateBackfillWorker()
    parent, children = _get_manifest_list_parent(initialized_db)

    ManifestBuildDate.delete().execute()

    for manifest in Manifest.select():
        if manifest.id == parent.id:
            continue
        is_child = any(c.child_manifest_id == manifest.id for c in children)
        if is_child:
            continue
        set_manifest_build_date(manifest.id, manifest.repository_id, None)

    assert not ManifestBuildDate.select().where(ManifestBuildDate.manifest == parent.id).exists()

    worker._backfill_manifest_build_dates()

    assert (
        not ManifestBuildDate.select().where(ManifestBuildDate.manifest == parent.id).exists()
    ), "Manifest list should NOT have a row while children are unprocessed"

    child_dates = []
    for i, child in enumerate(children):
        date_ms = (i + 1) * 5000000
        child_dates.append(date_ms)
        set_manifest_build_date(child.child_manifest_id, child.repository_id, date_ms)

    worker._backfill_manifest_build_dates()

    parent_build_date = get_manifest_build_date(parent.id)
    assert (
        parent_build_date is not None
    ), "Manifest list should have a build date after children are backfilled"
    assert parent_build_date == max(child_dates)


def test_full_backfill_manifest_lists_get_correct_dates(initialized_db):
    """End-to-end: running backfill to completion results in manifest lists
    having build dates that equal the MAX of their children's build dates,
    regardless of processing order."""
    worker = ManifestBuildDateBackfillWorker()

    while worker._backfill_manifest_build_dates():
        pass

    for child_entry in ManifestChild.select():
        parent_id = child_entry.manifest_id
        parent_date = get_manifest_build_date(parent_id)

        children = ManifestChild.select().where(ManifestChild.manifest == parent_id)
        child_dates = [get_manifest_build_date(c.child_manifest_id) for c in children]
        non_null_dates = [d for d in child_dates if d is not None]

        if non_null_dates:
            assert parent_date == max(non_null_dates), (
                f"Manifest list {parent_id} build_date={parent_date} "
                f"should equal max(children)={max(non_null_dates)}"
            )
