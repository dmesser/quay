import json

import pytest

from data.database import HelmChartMetadata, Manifest
from data.model.oci.helmchart import (
    get_helm_metadata_for_manifest,
    is_helm_chart,
    is_helm_manifest,
)
from data.model.repository import create_repository
from test.fixtures import *

HELM_CHART_CONFIG_TYPE = "application/vnd.cncf.helm.config.v1+json"
IMAGE_CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"

_DIGEST_COUNTER = [0]


def _hex_digest():
    _DIGEST_COUNTER[0] += 1
    return "sha256:" + format(_DIGEST_COUNTER[0], "064x")


def _create_helm_manifest(repo, digest):
    return Manifest.create(
        repository=repo,
        digest=digest,
        media_type=Manifest.media_type.rel_model.get(
            Manifest.media_type.rel_model.name == "application/vnd.oci.image.manifest.v1+json"
        ),
        manifest_bytes=json.dumps(
            {
                "schemaVersion": 2,
                "config": {
                    "mediaType": HELM_CHART_CONFIG_TYPE,
                    "digest": "sha256:abc",
                    "size": 100,
                },
                "layers": [],
            }
        ),
        config_media_type=HELM_CHART_CONFIG_TYPE,
        layers_compressed_size=0,
    )


def _create_image_manifest(repo, digest):
    return Manifest.create(
        repository=repo,
        digest=digest,
        media_type=Manifest.media_type.rel_model.get(
            Manifest.media_type.rel_model.name == "application/vnd.oci.image.manifest.v1+json"
        ),
        manifest_bytes="{}",
        config_media_type=IMAGE_CONFIG_TYPE,
        layers_compressed_size=0,
    )


class TestIsHelmChart:
    def test_true_for_helm_config_type(self):
        assert is_helm_chart(HELM_CHART_CONFIG_TYPE) is True

    def test_false_for_image_config_type(self):
        assert is_helm_chart(IMAGE_CONFIG_TYPE) is False

    def test_false_for_none(self):
        assert is_helm_chart(None) is False


class TestIsHelmManifest:
    def test_true_for_helm_manifest(self, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmcheck1", None)
        _create_helm_manifest(repo, digest)
        assert is_helm_manifest(repo.id, digest) is True

    def test_false_for_non_helm_manifest(self, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmcheck2", None)
        _create_image_manifest(repo, digest)
        assert is_helm_manifest(repo.id, digest) is False

    def test_false_for_nonexistent_manifest(self, initialized_db):
        repo = create_repository("devtable", "helmcheck3", None)
        assert is_helm_manifest(repo.id, _hex_digest()) is False

    def test_scoped_to_repository(self, initialized_db):
        """A Helm manifest in repo A is not found when queried against repo B."""
        digest = _hex_digest()
        repo_a = create_repository("devtable", "helmcheck4a", None)
        repo_b = create_repository("devtable", "helmcheck4b", None)
        _create_helm_manifest(repo_a, digest)
        assert is_helm_manifest(repo_a.id, digest) is True
        assert is_helm_manifest(repo_b.id, digest) is False


class TestGetHelmMetadataForManifest:
    def test_returns_metadata_when_exists(self, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmmeta1", None)
        m = _create_helm_manifest(repo, digest)
        HelmChartMetadata.create(
            manifest=m,
            repository=repo,
            chart_name="test-chart",
            chart_version="1.0.0",
            api_version="v2",
            chart_yaml="apiVersion: v2\nname: test-chart\nversion: 1.0.0\n",
            extraction_status="completed",
        )

        result = get_helm_metadata_for_manifest(repo.id, digest)
        assert result is not None
        assert result.chart_name == "test-chart"
        assert result.chart_version == "1.0.0"
        assert result.extraction_status == "completed"

    def test_returns_none_when_no_metadata(self, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmmeta2", None)
        _create_helm_manifest(repo, digest)

        result = get_helm_metadata_for_manifest(repo.id, digest)
        assert result is None

    def test_returns_none_when_no_manifest(self, initialized_db):
        repo = create_repository("devtable", "helmmeta3", None)
        result = get_helm_metadata_for_manifest(repo.id, _hex_digest())
        assert result is None

    def test_scoped_to_repository(self, initialized_db):
        """Metadata for a manifest in repo A is not returned when queried against repo B."""
        digest = _hex_digest()
        repo_a = create_repository("devtable", "helmmeta4a", None)
        repo_b = create_repository("devtable", "helmmeta4b", None)
        m = _create_helm_manifest(repo_a, digest)
        HelmChartMetadata.create(
            manifest=m,
            repository=repo_a,
            chart_name="scoped-chart",
            chart_version="1.0.0",
            api_version="v2",
            chart_yaml="apiVersion: v2\nname: scoped-chart\nversion: 1.0.0\n",
            extraction_status="completed",
        )

        assert get_helm_metadata_for_manifest(repo_a.id, digest) is not None
        assert get_helm_metadata_for_manifest(repo_b.id, digest) is None

    def test_returns_failed_metadata(self, initialized_db):
        """A metadata row with extraction_status='failed' is still returned."""
        digest = _hex_digest()
        repo = create_repository("devtable", "helmmeta5", None)
        m = _create_helm_manifest(repo, digest)
        HelmChartMetadata.create(
            manifest=m,
            repository=repo,
            chart_name="",
            chart_version="",
            api_version="",
            chart_yaml="",
            extraction_status="failed",
            extraction_error="corrupt archive",
        )

        result = get_helm_metadata_for_manifest(repo.id, digest)
        assert result is not None
        assert result.extraction_status == "failed"
        assert result.extraction_error == "corrupt archive"
