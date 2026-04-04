"""
Data access functions for Helm chart metadata.
"""

from data.database import HelmChartMetadata, Manifest

HELM_CHART_CONFIG_TYPE = "application/vnd.cncf.helm.config.v1+json"


def get_helm_metadata_for_manifest(repo_id, manifest_digest):
    """
    Returns the HelmChartMetadata row for the given repository and manifest digest,
    or None if not found.
    """
    try:
        return (
            HelmChartMetadata.select()
            .join(Manifest)
            .where(
                Manifest.repository == repo_id,
                Manifest.digest == manifest_digest,
            )
            .get()
        )
    except HelmChartMetadata.DoesNotExist:
        return None


def is_helm_manifest(repo_id, manifest_digest):
    """
    Returns True if the manifest exists in the given repository and has
    a Helm chart config media type.
    """
    try:
        manifest = (
            Manifest.select(Manifest.config_media_type)
            .where(
                Manifest.repository == repo_id,
                Manifest.digest == manifest_digest,
            )
            .get()
        )
        return manifest.config_media_type == HELM_CHART_CONFIG_TYPE
    except Manifest.DoesNotExist:
        return False


def is_helm_chart(config_media_type):
    """Returns True if the config_media_type identifies a Helm chart."""
    return config_media_type == HELM_CHART_CONFIG_TYPE
