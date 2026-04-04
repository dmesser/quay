"""
Tests for the Helm repository index API endpoints.
"""

from unittest.mock import MagicMock, patch

import pytest

from data.cache.cache_key import CacheKey
from data.cache.impl import InMemoryDataModelCache
from data.cache.test.test_cache import TEST_CACHE_CONFIG
from data.database import HelmRepoIndexConfig, Repository
from endpoints.api.helmrepoindex import RepositoryHelmRepoConfig
from endpoints.api.test.shared import conduct_api_call
from endpoints.test.shared import client_with_identity
from test.fixtures import *  # noqa: F401,F403


class TestRepositoryHelmRepoConfig:
    """Tests for GET/PUT /v1/repository/<repo>/helmrepo."""

    def test_get_default_config(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "GET",
                {"repository": "devtable/simple"},
            )
            assert result.json["enabled"] is False
            assert result.json["tagPattern"] is None

    def test_enable_config(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True},
            )
            assert result.json["enabled"] is True
            assert result.json["tagPattern"] is None

    def test_enable_with_null_tag_pattern(self, app, initialized_db):
        """Explicitly sending tagPattern: null should succeed."""
        with client_with_identity("devtable", app) as cl:
            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": None},
            )
            assert result.json["enabled"] is True
            assert result.json["tagPattern"] is None

    def test_disable_after_enable(self, app, initialized_db):
        """Toggling from enabled back to disabled should succeed."""
        with client_with_identity("devtable", app) as cl:
            conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "^v.*"},
            )

            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": False, "tagPattern": None},
            )
            assert result.json["enabled"] is False
            assert result.json["tagPattern"] is None

    def test_enable_with_pattern(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "^v[0-9]+.*"},
            )
            assert result.json["enabled"] is True
            assert result.json["tagPattern"] == "^v[0-9]+.*"

    def test_invalid_regex_pattern(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "[invalid"},
                expected_code=400,
            )
            assert "Invalid regex pattern" in result.json["detail"]

    def test_invalid_regex_various_patterns(self, app, initialized_db):
        """Multiple invalid patterns should all be rejected with descriptive errors."""
        invalid_patterns = ["(unclosed", "(?P<bad)", "*leading-quantifier"]
        with client_with_identity("devtable", app) as cl:
            for pattern in invalid_patterns:
                result = conduct_api_call(
                    cl,
                    RepositoryHelmRepoConfig,
                    "PUT",
                    {"repository": "devtable/simple"},
                    body={"enabled": True, "tagPattern": pattern},
                    expected_code=400,
                )
                assert (
                    "Invalid regex pattern" in result.json["detail"]
                ), f"Pattern {pattern!r} should be rejected"

    def test_pattern_too_long(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "x" * 300},
                expected_code=400,
            )

    def test_update_existing_config(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "^v1.*"},
            )

            result = conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True, "tagPattern": "^v2.*"},
            )
            assert result.json["tagPattern"] == "^v2.*"

    def test_nonexistent_repo(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "GET",
                {"repository": "devtable/nonexistent"},
                expected_code=404,
            )

    def test_put_invalidates_cache(self, app, initialized_db):
        """Updating the config invalidates the helm repo index cache."""
        with (
            client_with_identity("devtable", app) as cl,
            patch(
                "data.model.oci.helmrepoindex.invalidate_helm_repo_index_cache"
            ) as mock_invalidate,
        ):
            conduct_api_call(
                cl,
                RepositoryHelmRepoConfig,
                "PUT",
                {"repository": "devtable/simple"},
                body={"enabled": True},
            )

        mock_invalidate.assert_called_once()


class TestHelmRepoIndexWebRoute:
    """Tests for GET /<namespace>/<repo>/index.yaml (web route)."""

    def test_index_disabled(self, app, initialized_db):
        """Returns 404 when Helm repo index is not enabled for the repo."""
        with client_with_identity("devtable", app) as cl:
            resp = cl.get("/devtable/simple/index.yaml")
            assert resp.status_code == 404

    def test_index_enabled_empty(self, app, initialized_db):
        """Returns valid YAML when enabled but no Helm charts exist."""
        repo = Repository.get(Repository.name == "simple")
        HelmRepoIndexConfig.create(repository=repo, enabled=True)

        with client_with_identity("devtable", app) as cl:
            resp = cl.get("/devtable/simple/index.yaml")
            assert resp.status_code == 200
            assert resp.headers.get("Content-Type", "").startswith("application/x-yaml")

    def test_private_repo_unauthenticated(self, app, initialized_db):
        """Returns 401 with WWW-Authenticate header for private repos without credentials."""
        with app.test_client() as cl:
            resp = cl.get("/devtable/simple/index.yaml")
            assert resp.status_code == 401
            assert "WWW-Authenticate" in resp.headers
            assert resp.headers["WWW-Authenticate"] == 'Basic realm="Quay"'

    def test_nonexistent_repo(self, app, initialized_db):
        with client_with_identity("devtable", app) as cl:
            resp = cl.get("/devtable/nonexistent/index.yaml")
            assert resp.status_code == 404

    def test_index_response_is_cached(self, app, initialized_db):
        """Subsequent requests serve the cached index without regenerating."""
        repo = Repository.get(Repository.name == "simple")
        HelmRepoIndexConfig.create(repository=repo, enabled=True)

        cache = InMemoryDataModelCache(TEST_CACHE_CONFIG)

        with (
            client_with_identity("devtable", app) as cl,
            patch("app.model_cache", cache),
            patch(
                "data.model.oci.helmrepoindex.generate_helm_repo_index",
                wraps=__import__(
                    "data.model.oci.helmrepoindex", fromlist=["generate_helm_repo_index"]
                ).generate_helm_repo_index,
            ) as mock_generate,
        ):
            resp1 = cl.get("/devtable/simple/index.yaml")
            assert resp1.status_code == 200

            resp2 = cl.get("/devtable/simple/index.yaml")
            assert resp2.status_code == 200

            assert (
                mock_generate.call_count == 1
            ), f"Expected generate to be called once (cached), got {mock_generate.call_count}"

    def test_feature_flag_disabled(self, app, initialized_db):
        """Returns 404 when FEATURE_HELM_REPO_INDEX is disabled."""
        import features

        original = features.HELM_REPO_INDEX
        try:
            features.HELM_REPO_INDEX = False
            with client_with_identity("devtable", app) as cl:
                resp = cl.get("/devtable/simple/index.yaml")
                assert resp.status_code == 404
        finally:
            features.HELM_REPO_INDEX = original

    def test_malformed_repo_path(self, app, initialized_db):
        """Returns 404 for a path without a namespace/repo separator."""
        with client_with_identity("devtable", app) as cl:
            resp = cl.get("/singlecomponent/index.yaml")
            assert resp.status_code == 404

    def test_authenticated_user_without_permission(self, app, initialized_db):
        """Returns 403 for a user who is authenticated but has no read access."""
        repo = Repository.get(Repository.name == "simple")
        HelmRepoIndexConfig.create(repository=repo, enabled=True)

        with client_with_identity("public", app) as cl:
            resp = cl.get("/devtable/simple/index.yaml")
            assert resp.status_code == 403
