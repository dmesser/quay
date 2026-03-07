import logging

from peewee import JOIN, IntegrityError, fn

from data.database import ManifestBuildDate, ManifestChild

logger = logging.getLogger(__name__)


def set_manifest_build_date(manifest_id, repository_id, build_date_ms):
    """
    Insert the build date for a manifest. build_date_ms may be None
    (processed but no date available, e.g. artifacts).
    If a row already exists (race with backfill worker), the duplicate is silently ignored.
    """
    try:
        ManifestBuildDate.create(
            manifest=manifest_id,
            repository=repository_id,
            build_date=build_date_ms,
        )
    except IntegrityError:
        pass


def get_manifest_build_date(manifest_id):
    """Returns the build_date in epoch ms, or None if not found/not set."""
    try:
        row = ManifestBuildDate.get(ManifestBuildDate.manifest == manifest_id)
        return row.build_date
    except ManifestBuildDate.DoesNotExist:
        return None


def get_child_manifest_max_build_date(parent_manifest_id, repository_id):
    """For manifest lists: returns MAX(build_date) across all child manifests."""
    result = (
        ManifestBuildDate.select(fn.MAX(ManifestBuildDate.build_date))
        .join(ManifestChild, on=(ManifestBuildDate.manifest == ManifestChild.child_manifest))
        .where(
            ManifestChild.manifest == parent_manifest_id,
            ManifestChild.repository == repository_id,
        )
        .scalar()
    )
    return result


def has_unprocessed_children(parent_manifest_id, repository_id):
    """
    Returns True if any child manifest of the given parent does not yet have
    a ManifestBuildDate row, meaning it hasn't been backfilled yet.
    """
    return (
        ManifestChild.select()
        .join(
            ManifestBuildDate,
            JOIN.LEFT_OUTER,
            on=(ManifestChild.child_manifest == ManifestBuildDate.manifest),
        )
        .where(
            ManifestChild.manifest == parent_manifest_id,
            ManifestChild.repository == repository_id,
            ManifestBuildDate.id.is_null(),
        )
        .exists()
    )
