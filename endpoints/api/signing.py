"""
List and manage repository signing information.
"""

import logging

import features
from app import tuf_metadata_api
from endpoints.api import (
    NotFound,
    RepositoryParamResource,
    define_json_response,
    disallow_for_app_repositories,
    nickname,
    path_param,
    require_repo_read,
    resource,
    show_if,
)
from endpoints.api.signing_models_pre_oci import pre_oci_model as model

# Response schemas for signing endpoints
SIGNING_RESPONSE_SCHEMAS = {
    "TargetHashes": {
        "type": "object",
        "description": "Hash information for a target",
        "properties": {
            "sha256": {
                "type": "string",
                "description": "SHA256 hash of the target",
            },
        },
        "required": ["sha256"],
    },
    "Target": {
        "type": "object",
        "description": "A signed target with hash and size information",
        "properties": {
            "hashes": {
                "$ref": "#/definitions/TargetHashes",
            },
            "length": {
                "type": "integer",
                "description": "Size of the target in bytes",
            },
        },
        "required": ["hashes", "length"],
    },
    "Targets": {
        "type": "object",
        "description": "Collection of targets indexed by tag name",
        "additionalProperties": {
            "$ref": "#/definitions/Target",
        },
    },
    "Delegation": {
        "type": "object",
        "description": "A delegation with targets and expiration",
        "properties": {
            "targets": {
                "$ref": "#/definitions/Targets",
            },
            "expiration": {
                "type": "string",
                "description": "Expiration date of the delegation",
                "format": "date-time",
            },
        },
        "required": ["targets", "expiration"],
    },
    "Delegations": {
        "type": "object",
        "description": "Collection of delegations indexed by delegation name",
        "additionalProperties": {
            "oneOf": [
                {"$ref": "#/definitions/Delegation"},
                {"type": "null"},
            ],
        },
    },
    "SignaturesResponse": {
        "type": "object",
        "description": "Response containing all delegations for a repository",
        "properties": {
            "delegations": {
                "$ref": "#/definitions/Delegations",
            },
        },
        "required": ["delegations"],
    },
}

logger = logging.getLogger(__name__)


@resource("/v1/repository/<apirepopath:repository>/signatures")
@show_if(features.SIGNING)
@path_param("repository", "The full path of the repository. e.g. namespace/name")
class RepositorySignatures(RepositoryParamResource):
    """
    Operations for managing the signatures in a repository image.
    """

    schemas = SIGNING_RESPONSE_SCHEMAS

    @require_repo_read(allow_for_superuser=True)
    @nickname("getRepoSignatures")
    @disallow_for_app_repositories
    @define_json_response("SignaturesResponse")
    def get(self, namespace, repository):
        """
        Fetches the list of signed tags for the repository.
        """
        if not model.is_trust_enabled(namespace, repository):
            raise NotFound()

        return {"delegations": tuf_metadata_api.get_all_tags_with_expiration(namespace, repository)}
