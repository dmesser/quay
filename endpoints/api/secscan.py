"""
List and manage repository vulnerabilities and other security information.
"""

import logging
from enum import Enum, unique

import features
from app import model_cache, storage
from auth.decorators import process_basic_auth_no_pass
from data.registry_model import registry_model
from data.secscan_model import secscan_model
from data.secscan_model.datatypes import ScanLookupStatus
from endpoints.api import (
    RepositoryParamResource,
    define_json_response,
    deprecated,
    disallow_for_app_repositories,
    nickname,
    parse_args,
    path_param,
    query_param,
    require_repo_read,
    resource,
    show_if,
)
from endpoints.api.manifest import MANIFEST_DIGEST_ROUTE
from endpoints.decorators import anon_allowed
from endpoints.exception import DownstreamIssue, NotFound
from util.parsing import truthy_bool


@unique
class SecurityScanStatus(Enum):
    """
    Security scan status enum.
    """

    SCANNED = "scanned"
    FAILED = "failed"
    QUEUED = "queued"
    UNSUPPORTED = "unsupported"
    MANIFEST_LAYER_TOO_LARGE = "manifest_layer_too_large"


# Response schemas for security scan endpoints
SECURITY_RESPONSE_SCHEMAS = {
    "SecurityScanStatus": {
        "type": "string",
        "description": "Status of the security scan",
        "enum": ["scanned", "failed", "queued", "unsupported", "manifest_layer_too_large"],
    },
    "CVSSv3": {
        "type": "object",
        "description": "CVSS v3 scoring information",
        "properties": {
            "Vectors": {
                "type": ["string", "null"],
                "description": "CVSS v3 attack vectors string",
                "x-nullable": True,
            },
            "Score": {
                "type": ["number", "null"],
                "description": "CVSS v3 base score (can be a number or null)",
                "x-nullable": True,
            },
        },
    },
    "VulnerabilityMetadata": {
        "type": "object",
        "description": "Metadata for a vulnerability",
        "properties": {
            "UpdatedBy": {
                "type": ["string", "null"],
                "description": "Entity that updated the vulnerability information",
                "x-nullable": True,
            },
            "RepoName": {
                "type": ["string", "null"],
                "description": "Name of the repository containing the vulnerability",
                "x-nullable": True,
            },
            "RepoLink": {
                "type": ["string", "null"],
                "description": "Link to the repository",
                "x-nullable": True,
            },
            "DistroName": {
                "type": ["string", "null"],
                "description": "Distribution name",
                "x-nullable": True,
            },
            "DistroVersion": {
                "type": ["string", "null"],
                "description": "Distribution version",
                "x-nullable": True,
            },
            "NVD": {
                "$ref": "#/definitions/NVD",
            },
        },
        "required": ["UpdatedBy", "RepoName", "RepoLink", "DistroName", "DistroVersion", "NVD"],
    },
    "NVD": {
        "type": "object",
        "description": "National Vulnerability Database information",
        "properties": {
            "CVSSv3": {
                "$ref": "#/definitions/CVSSv3",
            },
        },
        "required": ["CVSSv3"],
    },
    "Vulnerability": {
        "type": "object",
        "description": "A security vulnerability",
        "properties": {
            "Severity": {
                "type": ["string", "null"],
                "description": "Severity level of the vulnerability",
                "enum": ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"],
                "x-nullable": True,
            },
            "NamespaceName": {
                "type": ["string", "null"],
                "description": "Namespace where the vulnerability was found",
                "x-nullable": True,
            },
            "Link": {
                "type": ["string", "null"],
                "description": "Link to vulnerability details",
                "x-nullable": True,
            },
            "FixedBy": {
                "type": ["string", "null"],
                "description": "Version that fixes the vulnerability",
                "x-nullable": True,
            },
            "Description": {
                "type": ["string", "null"],
                "description": "Description of the vulnerability",
                "x-nullable": True,
            },
            "Name": {
                "type": ["string", "null"],
                "description": "Name/ID of the vulnerability",
                "x-nullable": True,
            },
            "Metadata": {
                "$ref": "#/definitions/VulnerabilityMetadata",
            },
        },
        "required": [
            "Severity",
            "NamespaceName",
            "Link",
            "FixedBy",
            "Description",
            "Name",
            "Metadata",
        ],
    },
    "Feature": {
        "type": "object",
        "description": "A software feature/package with vulnerability information",
        "properties": {
            "Name": {
                "type": "string",
                "description": "Name of the feature/package",
            },
            "VersionFormat": {
                "type": "string",
                "description": "Format of the version string",
            },
            "NamespaceName": {
                "type": "string",
                "description": "Namespace of the feature",
            },
            "AddedBy": {
                "type": "string",
                "description": "Layer that added this feature",
            },
            "Version": {
                "type": "string",
                "description": "Version of the feature",
            },
            "BaseScores": {
                "type": "array",
                "description": "CVSS base scores for vulnerabilities in this feature",
                "items": {
                    "type": "number",
                },
            },
            "CVEIds": {
                "type": "array",
                "description": "CVE IDs for vulnerabilities in this feature",
                "items": {
                    "type": "string",
                },
            },
            "Vulnerabilities": {
                "type": "array",
                "description": "List of vulnerabilities in this feature",
                "items": {
                    "$ref": "#/definitions/Vulnerability",
                },
            },
        },
        "required": [
            "Name",
            "VersionFormat",
            "NamespaceName",
            "AddedBy",
            "Version",
            "BaseScores",
            "CVEIds",
            "Vulnerabilities",
        ],
    },
    "Layer": {
        "type": "object",
        "description": "A container layer with security information",
        "properties": {
            "Name": {
                "type": "string",
                "description": "Name/ID of the layer",
            },
            "ParentName": {
                "type": "string",
                "description": "Name of the parent layer",
            },
            "NamespaceName": {
                "type": "string",
                "description": "Namespace of the layer",
            },
            "IndexedByVersion": {
                "type": ["integer", "null"],
                "description": "Version of the indexer used",
                "x-nullable": True,
            },
            "Features": {
                "type": "array",
                "description": "Features found in this layer",
                "items": {
                    "$ref": "#/definitions/Feature",
                },
            },
        },
        "required": ["Name", "ParentName", "NamespaceName", "IndexedByVersion", "Features"],
    },
    "SecurityInformation": {
        "type": "object",
        "description": "Security information for a manifest",
        "properties": {
            "Layer": {
                "$ref": "#/definitions/Layer",
            },
        },
        "required": ["Layer"],
    },
    "SecurityScanResult": {
        "type": "object",
        "description": "Result of a security scan",
        "properties": {
            "status": {
                "$ref": "#/definitions/SecurityScanStatus",
            },
            "data": {
                "oneOf": [{"$ref": "#/definitions/SecurityInformation"}, {"type": "null"}],
                "x-nullable": True,
                "description": "Security information data, null if not available",
            },
        },
        "required": ["status"],
    },
}

MAPPED_STATUSES = {}
MAPPED_STATUSES[ScanLookupStatus.FAILED_TO_INDEX] = SecurityScanStatus.FAILED
MAPPED_STATUSES[ScanLookupStatus.SUCCESS] = SecurityScanStatus.SCANNED
MAPPED_STATUSES[ScanLookupStatus.NOT_YET_INDEXED] = SecurityScanStatus.QUEUED
MAPPED_STATUSES[ScanLookupStatus.UNSUPPORTED_FOR_INDEXING] = SecurityScanStatus.UNSUPPORTED
MAPPED_STATUSES[
    ScanLookupStatus.MANIFEST_LAYER_TOO_LARGE
] = SecurityScanStatus.MANIFEST_LAYER_TOO_LARGE

logger = logging.getLogger(__name__)


def _security_info(manifest_or_legacy_image, include_vulnerabilities=True):
    """
    Returns a dict representing the result of a call to the security status API for the given
    manifest or image.
    """
    result = secscan_model.load_security_information(
        manifest_or_legacy_image,
        include_vulnerabilities=include_vulnerabilities,
        model_cache=model_cache,
    )
    if result.status == ScanLookupStatus.UNKNOWN_MANIFEST_OR_IMAGE:
        raise NotFound()

    if result.status == ScanLookupStatus.COULD_NOT_LOAD:
        raise DownstreamIssue(result.scanner_request_error)

    assert result.status in MAPPED_STATUSES
    return {
        "status": MAPPED_STATUSES[result.status].value,
        "data": result.security_information.to_dict()
        if result.security_information is not None
        else None,
    }


@resource(MANIFEST_DIGEST_ROUTE + "/security")
@show_if(features.SECURITY_SCANNER)
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("manifestref", "The digest of the manifest")
class RepositoryManifestSecurity(RepositoryParamResource):
    """
    Operations for managing the vulnerabilities in a repository manifest.
    """

    schemas = SECURITY_RESPONSE_SCHEMAS

    @process_basic_auth_no_pass
    @anon_allowed
    @require_repo_read(allow_for_superuser=True)
    @nickname("getRepoManifestSecurity")
    @disallow_for_app_repositories
    @parse_args()
    @query_param(
        "vulnerabilities", "Include vulnerabilities informations", type=truthy_bool, default=False
    )
    @define_json_response("SecurityScanResult")
    def get(self, namespace, repository, manifestref, parsed_args):
        repo_ref = registry_model.lookup_repository(namespace, repository)
        if repo_ref is None:
            raise NotFound()

        manifest = registry_model.lookup_manifest_by_digest(repo_ref, manifestref, allow_dead=True)
        if manifest is None:
            raise NotFound()

        return _security_info(manifest, parsed_args.vulnerabilities)
