"""
API endpoints for Helm chart metadata associated with OCI manifests.
"""

import logging

import features
from data.model.oci.helmchart import get_helm_metadata_for_manifest, is_helm_manifest
from data.registry_model import registry_model
from digest import digest_tools
from endpoints.api import (
    RepositoryParamResource,
    nickname,
    path_param,
    require_repo_read,
    resource,
    show_if,
)
from endpoints.exception import NotFound

logger = logging.getLogger(__name__)

HELM_CHART_ROUTE = (
    '/v1/repository/<apirepopath:repository>/manifest/<regex("{0}"):manifestref>/helm'.format(
        digest_tools.DIGEST_PATTERN
    )
)

HELM_CHART_METADATA_SCHEMA = {
    "HelmChartMetadata": {
        "type": "object",
        "description": "Summary of Helm chart metadata for a manifest",
        "properties": {
            "extraction_status": {
                "type": "string",
                "description": "Status of metadata extraction: pending, completed, or failed",
                "enum": ["pending", "completed", "failed"],
            },
            "extraction_error": {
                "type": "string",
                "description": "Error message if extraction failed",
                "x-nullable": True,
            },
            "chart_name": {"type": "string", "description": "Name of the chart"},
            "chart_version": {"type": "string", "description": "Version of the chart"},
            "app_version": {
                "type": "string",
                "description": "Version of the application the chart deploys",
                "x-nullable": True,
            },
            "api_version": {
                "type": "string",
                "description": "Helm API version (v1 or v2)",
            },
            "description": {
                "type": "string",
                "description": "Short description of the chart",
                "x-nullable": True,
            },
            "kube_version": {
                "type": "string",
                "description": "Required Kubernetes version constraint",
                "x-nullable": True,
            },
            "chart_type": {
                "type": "string",
                "description": "Type of the chart (application or library)",
                "x-nullable": True,
            },
            "home": {
                "type": "string",
                "description": "URL of the chart's home page",
                "x-nullable": True,
            },
            "deprecated": {"type": "boolean", "description": "Whether the chart is deprecated"},
            "sources": {
                "type": "array",
                "description": "List of source code URLs",
                "items": {"type": "string"},
            },
            "maintainers": {
                "type": "array",
                "description": "List of chart maintainers",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"},
                        "url": {"type": "string"},
                    },
                },
            },
            "dependencies": {
                "type": "array",
                "description": "List of chart dependencies",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "version": {"type": "string"},
                        "repository": {"type": "string"},
                    },
                },
            },
            "keywords": {
                "type": "array",
                "description": "List of keywords",
                "items": {"type": "string"},
            },
            "annotations": {
                "type": "object",
                "description": "Arbitrary key-value annotations from Chart.yaml",
            },
            "has_readme": {"type": "boolean", "description": "Whether a README is available"},
            "has_values": {
                "type": "boolean",
                "description": "Whether a values.yaml is available",
            },
            "has_schema": {
                "type": "boolean",
                "description": "Whether a values.schema.json is available",
            },
            "has_provenance": {
                "type": "boolean",
                "description": "Whether a provenance file is available",
            },
            "has_icon": {"type": "boolean", "description": "Whether an icon is available"},
            "icon_media_type": {
                "type": "string",
                "description": "Media type of the icon",
                "x-nullable": True,
            },
            "file_tree": {
                "type": "array",
                "description": "List of files in the chart archive",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "size": {"type": "integer"},
                    },
                },
            },
            "image_references": {
                "type": "array",
                "description": "Container image references found in the chart",
                "items": {
                    "type": "object",
                    "properties": {
                        "image": {"type": "string"},
                        "source": {"type": "string"},
                    },
                },
            },
            "provenance_key_id": {
                "type": "string",
                "description": "PGP key ID used to sign the chart",
                "x-nullable": True,
            },
            "provenance_hash_algorithm": {
                "type": "string",
                "description": "Hash algorithm used in the provenance signature",
                "x-nullable": True,
            },
            "provenance_signature_date": {
                "type": "string",
                "description": "ISO 8601 timestamp of the provenance signature",
                "x-nullable": True,
            },
        },
    },
    "HelmChartContent": {
        "type": "object",
        "description": "Text content from a Helm chart (readme, values, schema, provenance)",
        "required": ["content"],
        "properties": {
            "content": {"type": "string", "description": "The text content"},
        },
    },
    "HelmChartIcon": {
        "type": "object",
        "description": "Base64-encoded icon data for a Helm chart",
        "required": ["icon_data", "media_type"],
        "properties": {
            "icon_data": {
                "type": "string",
                "description": "Base64-encoded icon image data",
            },
            "media_type": {
                "type": "string",
                "description": "Media type of the icon (e.g. image/png)",
            },
        },
    },
}


def _lookup_helm_metadata(namespace_name, repository_name, manifestref):
    """
    Look up the repository and HelmChartMetadata row. Raises NotFound
    if either is missing.
    """
    repo_ref = registry_model.lookup_repository(namespace_name, repository_name)
    if repo_ref is None:
        raise NotFound()

    metadata = get_helm_metadata_for_manifest(repo_ref.id, manifestref)
    if metadata is None:
        raise NotFound()

    return metadata


@resource(HELM_CHART_ROUTE)
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChart(RepositoryParamResource):
    """
    Resource for retrieving Helm chart metadata summary for a manifest.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartMetadata")
    def get(self, namespace_name, repository_name, manifestref):
        repo_ref = registry_model.lookup_repository(namespace_name, repository_name)
        if repo_ref is None:
            raise NotFound()

        metadata = get_helm_metadata_for_manifest(repo_ref.id, manifestref)

        if metadata is None:
            if is_helm_manifest(repo_ref.id, manifestref):
                return {"extraction_status": "pending"}
            raise NotFound()

        return {
            "extraction_status": metadata.extraction_status,
            "chart_name": metadata.chart_name,
            "chart_version": metadata.chart_version,
            "app_version": metadata.app_version,
            "api_version": metadata.api_version,
            "description": metadata.description,
            "kube_version": metadata.kube_version,
            "chart_type": metadata.chart_type,
            "home": metadata.home,
            "deprecated": metadata.deprecated,
            "sources": metadata.sources,
            "maintainers": metadata.maintainers,
            "dependencies": metadata.chart_dependencies,
            "keywords": metadata.keywords,
            "annotations": metadata.annotations,
            "has_readme": metadata.readme is not None,
            "has_values": metadata.values_yaml is not None,
            "has_schema": metadata.values_schema_json is not None,
            "has_provenance": metadata.provenance is not None,
            "has_icon": metadata.icon_data is not None,
            "icon_media_type": metadata.icon_media_type,
            "file_tree": metadata.file_tree,
            "image_references": metadata.image_references,
            "extraction_error": metadata.extraction_error,
            "provenance_key_id": metadata.provenance_key_id,
            "provenance_hash_algorithm": metadata.provenance_hash_algorithm,
            "provenance_signature_date": metadata.provenance_signature_date,
        }


@resource(HELM_CHART_ROUTE + "/readme")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChartReadme(RepositoryParamResource):
    """
    Resource for retrieving the README of a Helm chart.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartReadme")
    def get(self, namespace_name, repository_name, manifestref):
        metadata = _lookup_helm_metadata(namespace_name, repository_name, manifestref)

        if metadata.readme is None:
            raise NotFound()

        return {"content": metadata.readme}


@resource(HELM_CHART_ROUTE + "/values")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChartValues(RepositoryParamResource):
    """
    Resource for retrieving the values.yaml of a Helm chart.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartValues")
    def get(self, namespace_name, repository_name, manifestref):
        metadata = _lookup_helm_metadata(namespace_name, repository_name, manifestref)

        if metadata.values_yaml is None:
            raise NotFound()

        return {"content": metadata.values_yaml}


@resource(HELM_CHART_ROUTE + "/schema")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChartSchema(RepositoryParamResource):
    """
    Resource for retrieving the values.schema.json of a Helm chart.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartSchema")
    def get(self, namespace_name, repository_name, manifestref):
        metadata = _lookup_helm_metadata(namespace_name, repository_name, manifestref)

        if metadata.values_schema_json is None:
            raise NotFound()

        return {"content": metadata.values_schema_json}


@resource(HELM_CHART_ROUTE + "/icon")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChartIcon(RepositoryParamResource):
    """
    Resource for retrieving the icon of a Helm chart.
    Returns the icon as base64-encoded data with its media type.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartIcon")
    def get(self, namespace_name, repository_name, manifestref):
        metadata = _lookup_helm_metadata(namespace_name, repository_name, manifestref)

        if metadata.icon_data is None:
            raise NotFound()

        return {
            "icon_data": metadata.icon_data,
            "media_type": metadata.icon_media_type,
        }


@resource(HELM_CHART_ROUTE + "/provenance")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
@show_if(features.HELM_CHART_METADATA_EXTRACTION)
class RepositoryManifestHelmChartProvenance(RepositoryParamResource):
    """
    Resource for retrieving the provenance file of a Helm chart.
    """

    schemas = HELM_CHART_METADATA_SCHEMA

    @require_repo_read(allow_for_superuser=True, allow_for_global_readonly_superuser=True)
    @nickname("getHelmChartProvenance")
    def get(self, namespace_name, repository_name, manifestref):
        metadata = _lookup_helm_metadata(namespace_name, repository_name, manifestref)

        if metadata.provenance is None:
            raise NotFound()

        return {"content": metadata.provenance}
