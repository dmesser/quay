import json

import pytest

from data.database import HelmChartMetadata, Manifest, Repository
from data.model.repository import create_repository
from data.registry_model import registry_model
from endpoints.api.helmchart import (
    RepositoryManifestHelmChart,
    RepositoryManifestHelmChartIcon,
    RepositoryManifestHelmChartProvenance,
    RepositoryManifestHelmChartReadme,
    RepositoryManifestHelmChartSchema,
    RepositoryManifestHelmChartValues,
)
from endpoints.api.manifest import RepositoryManifest
from endpoints.api.tag import ListRepositoryTags
from endpoints.api.test.shared import conduct_api_call
from endpoints.test.shared import client_with_identity
from test.fixtures import *

HELM_CHART_CONFIG_TYPE = "application/vnd.cncf.helm.config.v1+json"

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


def _create_full_helm_metadata(manifest, repo):
    return HelmChartMetadata.create(
        manifest=manifest,
        repository=repo,
        chart_name="nginx",
        chart_version="1.2.3",
        app_version="1.25.0",
        api_version="v2",
        description="A Helm chart for Kubernetes",
        kube_version=">=1.20.0",
        chart_type="application",
        home="https://nginx.org",
        deprecated=False,
        sources=["https://github.com/nginx/nginx"],
        maintainers=[{"name": "maintainer", "email": "m@example.com"}],
        chart_dependencies=[
            {"name": "common", "version": "2.x", "repository": "https://charts.example.com"}
        ],
        keywords=["nginx", "web"],
        annotations={"category": "web"},
        chart_yaml="apiVersion: v2\nname: nginx\nversion: 1.2.3\n",
        readme="# Nginx Chart\n\nA chart for deploying Nginx.",
        values_yaml="replicaCount: 1\nimage:\n  tag: latest\n",
        values_schema_json='{"type": "object", "properties": {"replicaCount": {"type": "integer"}}}',
        provenance="-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\nchart content\n",
        provenance_key_id="0000111122223333",
        provenance_hash_algorithm="SHA512",
        provenance_signature_date="2026-01-15T10:30:00+00:00",
        icon_data="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA",
        icon_media_type="image/png",
        file_tree=[
            {"path": "Chart.yaml", "size": 200},
            {"path": "templates/deployment.yaml", "size": 1234},
        ],
        image_references=[{"image": "nginx:1.25", "location": "templates/deployment.yaml"}],
        extraction_status="completed",
    )


def _minimal_helm_metadata(manifest, repo, **overrides):
    defaults = dict(
        manifest=manifest,
        repository=repo,
        chart_name="minimal",
        chart_version="1.0.0",
        api_version="v2",
        chart_yaml="apiVersion: v2\nname: minimal\nversion: 1.0.0\n",
        extraction_status="completed",
    )
    defaults.update(overrides)
    return HelmChartMetadata.create(**defaults)


class TestRepositoryManifestHelmChart:
    def test_get_helm_metadata_completed(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmtest", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmtest", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChart, "GET", params, None, 200
            ).json

        assert result["extraction_status"] == "completed"
        assert result["chart_name"] == "nginx"
        assert result["chart_version"] == "1.2.3"
        assert result["app_version"] == "1.25.0"
        assert result["api_version"] == "v2"
        assert result["description"] == "A Helm chart for Kubernetes"
        assert result["deprecated"] is False
        assert result["has_readme"] is True
        assert result["has_values"] is True
        assert result["has_schema"] is True
        assert result["has_provenance"] is True
        assert result["has_icon"] is True
        assert result["icon_media_type"] == "image/png"
        assert len(result["file_tree"]) == 2
        assert len(result["image_references"]) == 1
        assert result["keywords"] == ["nginx", "web"]
        assert result["provenance_key_id"] == "0000111122223333"
        assert result["provenance_hash_algorithm"] == "SHA512"
        assert result["provenance_signature_date"] == "2026-01-15T10:30:00+00:00"

    def test_get_helm_metadata_pending(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmtest2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(
            m, repo, chart_name="pending-chart", chart_version="0.1.0", extraction_status="pending"
        )

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmtest2", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChart, "GET", params, None, 200
            ).json

        assert result["extraction_status"] == "pending"
        assert result["has_readme"] is False
        assert result["has_values"] is False

    def test_get_helm_metadata_failed(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmfailed", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(
            m,
            repo,
            chart_name="broken-chart",
            chart_version="0.1.0",
            extraction_status="failed",
            extraction_error="unable to decompress chart archive",
        )

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmfailed", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChart, "GET", params, None, 200
            ).json

        assert result["extraction_status"] == "failed"
        assert result["extraction_error"] == "unable to decompress chart archive"

    def test_get_helm_metadata_nonexistent_manifest(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/simple", "manifestref": _hex_digest()}
            conduct_api_call(cl, RepositoryManifestHelmChart, "GET", params, None, 404)

    def test_get_helm_metadata_pending_when_no_metadata_row(self, app, initialized_db):
        """A Helm manifest with no HelmChartMetadata row returns extraction_status: pending."""
        digest = _hex_digest()
        repo = create_repository("devtable", "helmtest3", None)
        _create_helm_manifest(repo, digest)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmtest3", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChart, "GET", params, None, 200
            ).json

        assert result["extraction_status"] == "pending"
        assert len(result) == 1

    def test_get_helm_metadata_404_for_non_helm_manifest(self, app, initialized_db):
        """A non-Helm manifest with no HelmChartMetadata row returns 404."""
        digest = _hex_digest()
        repo = create_repository("devtable", "helmtest4", None)
        Manifest.create(
            repository=repo,
            digest=digest,
            media_type=Manifest.media_type.rel_model.get(
                Manifest.media_type.rel_model.name == "application/vnd.oci.image.manifest.v1+json"
            ),
            manifest_bytes="{}",
            config_media_type="application/vnd.oci.image.config.v1+json",
            layers_compressed_size=0,
        )

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmtest4", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChart, "GET", params, None, 404)

    def test_get_helm_metadata_nonexistent_repo(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/doesnotexist", "manifestref": _hex_digest()}
            conduct_api_call(cl, RepositoryManifestHelmChart, "GET", params, None, 404)


class TestRepositoryManifestHelmChartReadme:
    def test_get_readme(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmreadme", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmreadme", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChartReadme, "GET", params, None, 200
            ).json

        assert "# Nginx Chart" in result["content"]

    def test_get_readme_not_available(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmreadme2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(m, repo, chart_name="no-readme")

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmreadme2", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChartReadme, "GET", params, None, 404)


class TestRepositoryManifestHelmChartValues:
    def test_get_values(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmvalues", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmvalues", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChartValues, "GET", params, None, 200
            ).json

        assert "replicaCount" in result["content"]

    def test_get_values_not_available(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmvalues2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(m, repo, chart_name="no-values")

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmvalues2", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChartValues, "GET", params, None, 404)


class TestRepositoryManifestHelmChartSchema:
    def test_get_schema(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmschema", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmschema", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChartSchema, "GET", params, None, 200
            ).json

        assert "replicaCount" in result["content"]

    def test_get_schema_not_available(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmschema2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(m, repo, chart_name="no-schema")

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmschema2", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChartSchema, "GET", params, None, 404)


class TestRepositoryManifestHelmChartIcon:
    def test_get_icon(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmicon", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmicon", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChartIcon, "GET", params, None, 200
            ).json

        assert result["media_type"] == "image/png"
        assert len(result["icon_data"]) > 0

    def test_get_icon_not_available(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmicon2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(m, repo, chart_name="no-icon")

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmicon2", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChartIcon, "GET", params, None, 404)


class TestRepositoryManifestHelmChartProvenance:
    def test_get_provenance(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmprov", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmprov", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChartProvenance, "GET", params, None, 200
            ).json

        assert "PGP SIGNED" in result["content"]

    def test_get_provenance_not_available(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmprov2", None)
        m = _create_helm_manifest(repo, digest)
        _minimal_helm_metadata(m, repo, chart_name="no-prov")

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmprov2", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChartProvenance, "GET", params, None, 404)


class TestManifestIsHelmChartFlag:
    def test_non_helm_manifest_has_no_is_helm_chart(self, app, initialized_db):
        repo_ref = registry_model.lookup_repository("devtable", "simple")
        tags = registry_model.list_all_active_repository_tags(repo_ref)
        manifest_digest = None
        for tag in tags:
            if tag and tag.manifest_digest:
                manifest_digest = tag.manifest_digest
                break

        assert manifest_digest is not None

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/simple", "manifestref": manifest_digest}
            result = conduct_api_call(cl, RepositoryManifest, "GET", params, None, 200).json

        assert "is_helm_chart" not in result


class TestTagIsHelmChartFlag:
    def test_tag_response_includes_is_helm_chart(self, app, initialized_db):
        from data.database import Tag

        digest = _hex_digest()
        repo = create_repository("devtable", "helmtag", None)
        m = _create_helm_manifest(repo, digest)
        Tag.create(
            name="latest",
            repository=repo,
            manifest=m,
            tag_kind=Tag.tag_kind.rel_model.get(Tag.tag_kind.rel_model.name == "tag"),
            lifetime_start=1,
        )

        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/helmtag"}
            result = conduct_api_call(cl, ListRepositoryTags, "GET", params, None, 200).json

        helm_tags = [t for t in result["tags"] if t.get("is_helm_chart")]
        assert len(helm_tags) == 1
        assert helm_tags[0]["name"] == "latest"
        assert helm_tags[0]["is_helm_chart"] is True

    def test_non_helm_tag_has_no_is_helm_chart(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            params = {"repository": "devtable/simple"}
            result = conduct_api_call(cl, ListRepositoryTags, "GET", params, None, 200).json

        for tag in result["tags"]:
            assert "is_helm_chart" not in tag


class TestHelmAnonymousAccess:
    def test_anonymous_can_read_helm_on_public_repo(self, app, initialized_db):
        digest = _hex_digest()
        repo_ref = registry_model.lookup_repository("public", "publicrepo")
        repo = Repository.get(Repository.id == repo_ref.id)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity(None, app) as cl:
            params = {"repository": "public/publicrepo", "manifestref": digest}
            result = conduct_api_call(
                cl, RepositoryManifestHelmChart, "GET", params, None, 200
            ).json

        assert result["chart_name"] == "nginx"

    def test_anonymous_cannot_read_helm_on_private_repo(self, app, initialized_db):
        digest = _hex_digest()
        repo = create_repository("devtable", "helmprivate", None)
        m = _create_helm_manifest(repo, digest)
        _create_full_helm_metadata(m, repo)

        with client_with_identity(None, app) as cl:
            params = {"repository": "devtable/helmprivate", "manifestref": digest}
            conduct_api_call(cl, RepositoryManifestHelmChart, "GET", params, None, 401)
