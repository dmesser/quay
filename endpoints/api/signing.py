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
    "SignaturesResponse": {
        "type": "object",
        "description": "Response containing delegation names for a repository",
        "properties": {
            "delegations": {
                "type": "array",
                "description": "List of delegation names",
                "items": {"type": "string", "description": "Name of a delegation role"},
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

        signed = tuf_metadata_api.get_all_tags_with_expiration(namespace, repository)
        delegations = signed.get("delegations")
        if delegations and delegations.get("roles"):
            delegation_names = [role.get("name") for role in delegations.get("roles")]
        else:
            delegation_names = []

        return {"delegations": delegation_names}
