"""
API endpoint for Helm repository index configuration.
"""

import logging

import regex
from flask import request

import features
from data.database import HelmRepoIndexConfig
from data.database import Repository as _Repository
from data.registry_model import registry_model
from endpoints.api import (
    RepositoryParamResource,
    nickname,
    path_param,
    require_repo_admin,
    require_repo_read,
    resource,
    show_if,
    validate_json_request,
)
from endpoints.exception import InvalidRequest, NotFound

logger = logging.getLogger(__name__)

HELM_REPO_CONFIG_ROUTE = "/v1/repository/<apirepopath:repository>/helmrepo"

HELM_REPO_INDEX_CONFIG_SCHEMA = {
    "HelmRepoIndexConfig": {
        "type": "object",
        "description": "Configuration for Helm repository index generation",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "Whether the Helm repository index is enabled for this repository",
            },
            "tagPattern": {
                "type": ["string", "null"],
                "description": "Optional regex pattern to filter which tags are included in the index",
            },
        },
    },
}


def get_helm_repo_config(repo_id):
    """Get the HelmRepoIndexConfig for a repository, or None if not configured."""
    try:
        return HelmRepoIndexConfig.get(HelmRepoIndexConfig.repository == repo_id)
    except HelmRepoIndexConfig.DoesNotExist:
        return None


@resource(HELM_REPO_CONFIG_ROUTE)
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@show_if(features.HELM_REPO_INDEX)
class RepositoryHelmRepoConfig(RepositoryParamResource):
    """Resource for managing the Helm repository index configuration."""

    schemas = HELM_REPO_INDEX_CONFIG_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmRepoConfig")
    def get(self, namespace, repository):
        repo_ref = registry_model.lookup_repository(namespace, repository)
        if repo_ref is None:
            raise NotFound()

        config = get_helm_repo_config(repo_ref.id)
        return {
            "enabled": config.enabled if config else False,
            "tagPattern": config.tag_pattern if config else None,
        }

    @require_repo_admin(allow_for_superuser=True)
    @nickname("updateHelmRepoConfig")
    @validate_json_request("HelmRepoIndexConfig")
    def put(self, namespace, repository):
        repo_ref = registry_model.lookup_repository(namespace, repository)
        if repo_ref is None:
            raise NotFound()

        data = request.get_json()
        enabled = data.get("enabled", False)
        tag_pattern = data.get("tagPattern")

        if tag_pattern is not None:
            tag_pattern = tag_pattern.strip()
            if tag_pattern:
                if len(tag_pattern) > 256:
                    raise InvalidRequest("Tag pattern must be 256 characters or less")
                try:
                    regex.compile(tag_pattern)
                except regex.error as e:
                    raise InvalidRequest(f"Invalid regex pattern: {e}")
            else:
                tag_pattern = None

        repo = _Repository.get(_Repository.id == repo_ref.id)
        config = get_helm_repo_config(repo.id)
        if config:
            config.enabled = enabled
            config.tag_pattern = tag_pattern
            config.save()
        else:
            config = HelmRepoIndexConfig.create(
                repository=repo, enabled=enabled, tag_pattern=tag_pattern
            )

        from data.model.oci.helmrepoindex import invalidate_helm_repo_index_cache

        invalidate_helm_repo_index_cache(repo.id)

        return {
            "enabled": config.enabled,
            "tagPattern": config.tag_pattern,
        }
