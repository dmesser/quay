import logging
import logging.config
import time
from math import log10

from peewee import JOIN, fn
from prometheus_client import Counter, Gauge, Histogram

import features
from app import app
from data.database import CloseForLongOperation, Manifest, ManifestBuildDate
from data.model.oci.build_date import (
    get_child_manifest_max_build_date,
    has_unprocessed_children,
    set_manifest_build_date,
)
from data.model.oci.retriever import RepositoryContentRetriever
from image.shared.schemas import parse_manifest_from_bytes
from util.bytes import Bytes
from util.log import logfile_path
from util.migrate.allocator import yield_random_entries
from workers.gunicorn_worker import GunicornWorker
from workers.worker import Worker

logger = logging.getLogger(__name__)

WORKER_FREQUENCY = app.config.get("MANIFEST_BUILD_DATE_BACKFILL_WORKER_FREQUENCY", 60)

build_date_manifests_remaining = Gauge(
    "quay_manifest_build_date_remaining",
    "Number of manifests not yet processed by the build date backfill worker",
)

build_date_manifests_backfilled = Counter(
    "quay_manifest_build_date_backfilled_total",
    "Total number of manifests processed by the build date backfill worker",
    labelnames=["status"],
)

build_date_backfill_duration = Histogram(
    "quay_manifest_build_date_backfill_duration_seconds",
    "Time spent per manifest in the build date backfill worker",
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0),
)


_DEFER = object()


class ManifestBuildDateBackfillWorker(Worker):
    """
    Worker which backfills the ManifestBuildDate table for manifests that
    do not yet have a corresponding row (i.e. existing images pushed before
    the build date feature was enabled).
    """

    def __init__(self):
        super().__init__()
        self.add_operation(self._backfill_manifest_build_dates, WORKER_FREQUENCY)

    def _unprocessed_query(self):
        return (
            Manifest.select()
            .join(
                ManifestBuildDate,
                JOIN.LEFT_OUTER,
                on=(Manifest.id == ManifestBuildDate.manifest),
            )
            .where(ManifestBuildDate.id >> None)
        )

    def _backfill_manifest_build_dates(self):
        try:
            self._unprocessed_query().limit(1).get()
        except Manifest.DoesNotExist:
            logger.info("Build date backfill complete; no remaining work")
            build_date_manifests_remaining.set(0)
            return False

        max_id = Manifest.select(fn.Max(Manifest.id)).scalar()
        min_id = Manifest.select(fn.Min(Manifest.id)).scalar() or 0
        batch_size = int(4 ** log10(max(10, max_id - min_id)))

        iterator = yield_random_entries(
            self._unprocessed_query,
            Manifest.id,
            batch_size,
            max_id,
            min_id,
        )

        for manifest_row, abt, num_remaining in iterator:
            build_date_manifests_remaining.set(num_remaining)

            if (
                ManifestBuildDate.select()
                .where(ManifestBuildDate.manifest == manifest_row.id)
                .exists()
            ):
                build_date_manifests_backfilled.labels(status="skipped").inc()
                abt.set()
                continue

            with build_date_backfill_duration.time():
                build_date_ms = self._extract_build_date(manifest_row)

            if build_date_ms is _DEFER:
                build_date_manifests_backfilled.labels(status="deferred").inc()
                continue

            set_manifest_build_date(manifest_row.id, manifest_row.repository_id, build_date_ms)
            build_date_manifests_backfilled.labels(status="success").inc()

        delay = app.config.get("MANIFEST_BUILD_DATE_BACKFILL_DELAY_SECONDS", 0)
        if delay:
            time.sleep(delay)

        return True

    def _extract_build_date(self, manifest_row):
        """
        Extract the build date from a manifest row. Returns epoch milliseconds, None,
        or _DEFER. On error, logs a warning and returns None (so a NULL row is still
        created to prevent re-processing).

        Returns _DEFER for manifest lists whose children haven't been backfilled yet,
        signalling the caller to skip row creation so the manifest list is retried later.

        Priority: OCI annotations (org.opencontainers.image.created) are checked first
        via get_image_created_datetime. For manifest lists/indexes without an annotation,
        falls back to MAX(child build dates).
        """
        try:
            manifest_bytes = manifest_row.manifest_bytes
            if not manifest_bytes:
                return None

            parsed = parse_manifest_from_bytes(
                Bytes.for_string_or_unicode(manifest_bytes),
                manifest_row.media_type.name,
                validate=False,
            )

            storage = app.config.get("DISTRIBUTED_STORAGE_CONFIG", {})
            retriever = None
            if storage:
                with CloseForLongOperation(app.config):
                    retriever = RepositoryContentRetriever.for_repository(
                        manifest_row.repository_id,
                        app.storage,
                    )
                    created_dt = parsed.get_image_created_datetime(retriever)

                if created_dt is not None:
                    return int(created_dt.timestamp() * 1000)

            if parsed.is_manifest_list:
                if has_unprocessed_children(manifest_row.id, manifest_row.repository_id):
                    return _DEFER
                return get_child_manifest_max_build_date(
                    manifest_row.id, manifest_row.repository_id
                )

            return None

        except Exception:
            logger.warning(
                "Failed to extract build date for manifest %s",
                manifest_row.id,
                exc_info=True,
            )
            build_date_manifests_backfilled.labels(status="error").inc()
            return None


def create_gunicorn_worker():
    """
    Follows the gunicorn application factory pattern, enabling
    a quay worker to run as a gunicorn worker thread.
    """
    worker = GunicornWorker(
        __name__,
        app,
        ManifestBuildDateBackfillWorker(),
        features.MANIFEST_BUILD_DATE_BACKFILL,
    )
    return worker


def main():
    logging.config.fileConfig(logfile_path(debug=False), disable_existing_loggers=False)

    if app.config.get("ACCOUNT_RECOVERY_MODE", False):
        logger.debug("Quay running in account recovery mode")
        while True:
            time.sleep(100000)

    if not features.MANIFEST_BUILD_DATE_BACKFILL:
        logger.debug("Manifest build date backfill worker not enabled; skipping")
        while True:
            time.sleep(100000)

    worker = ManifestBuildDateBackfillWorker()
    worker.start()


if __name__ == "__main__":
    main()
