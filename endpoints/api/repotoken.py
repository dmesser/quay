"""
Manage repository access tokens (DEPRECATED).
"""

import logging

from endpoints.api import (
    RepositoryParamResource,
    define_json_response,
    nickname,
    path_param,
    require_repo_admin,
    resource,
    validate_json_request,
)

logger = logging.getLogger(__name__)

# Shared schema definitions
DEPRECATION_RESPONSE_SCHEMA = {
    "DeprecationResponse": {
        "type": "object",
        "description": "Deprecation message for repository token endpoints",
        "properties": {
            "message": {
                "type": "string",
                "description": "Deprecation message indicating the endpoint is no longer supported",
                "enum": [
                    "Handling of access tokens is no longer supported",
                    "Creation of access tokens is no longer supported",
                ],
            },
        },
        "required": ["message"],
    },
}


@resource("/v1/repository/<apirepopath:repository>/tokens/")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
class RepositoryTokenList(RepositoryParamResource):
    """
    Resource for creating and listing repository tokens.
    """

    schemas = {
        "NewToken": {
            "type": "object",
            "description": "Description of a new token.",
            "required": [
                "friendlyName",
            ],
            "properties": {
                "friendlyName": {
                    "type": "string",
                    "description": "Friendly name to help identify the token",
                },
            },
        },
        **DEPRECATION_RESPONSE_SCHEMA,
    }

    @require_repo_admin(allow_for_superuser=True)
    @nickname("listRepoTokens")
    @define_json_response("DeprecationResponse")
    def get(self, namespace_name, repo_name):
        """
        List the tokens for the specified repository.
        """
        return {
            "message": "Handling of access tokens is no longer supported",
        }, 410

    @require_repo_admin(allow_for_superuser=True)
    @nickname("createToken")
    @validate_json_request("NewToken")
    @define_json_response("DeprecationResponse")
    def post(self, namespace_name, repo_name):
        """
        Create a new repository token.
        """
        return {
            "message": "Creation of access tokens is no longer supported",
        }, 410


@resource("/v1/repository/<apirepopath:repository>/tokens/<code>")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("code", "The token code")
class RepositoryToken(RepositoryParamResource):
    """
    Resource for managing individual tokens.
    """

    schemas = {
        "TokenPermission": {
            "type": "object",
            "description": "Description of a token permission",
            "required": [
                "role",
            ],
            "properties": {
                "role": {
                    "type": "string",
                    "description": "Role to use for the token",
                    "enum": [
                        "read",
                        "write",
                        "admin",
                    ],
                },
            },
        },
        **DEPRECATION_RESPONSE_SCHEMA,
    }

    @require_repo_admin(allow_for_superuser=True)
    @nickname("getTokens")
    @define_json_response("DeprecationResponse")
    def get(self, namespace_name, repo_name, code):
        """
        Fetch the specified repository token information.
        """
        return {
            "message": "Handling of access tokens is no longer supported",
        }, 410

    @require_repo_admin(allow_for_superuser=True)
    @nickname("changeToken")
    @validate_json_request("TokenPermission")
    @define_json_response("DeprecationResponse")
    def put(self, namespace_name, repo_name, code):
        """
        Update the permissions for the specified repository token.
        """
        return {
            "message": "Handling of access tokens is no longer supported",
        }, 410

    @require_repo_admin(allow_for_superuser=True)
    @nickname("deleteToken")
    @define_json_response("DeprecationResponse")
    def delete(self, namespace_name, repo_name, code):
        """
        Delete the repository token.
        """
        return {
            "message": "Handling of access tokens is no longer supported",
        }, 410
