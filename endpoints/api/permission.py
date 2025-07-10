"""
Manage repository permissions.
"""

import logging

from flask import request

from .permission_models_interface import DeleteException, SaveException
from .permission_models_pre_oci import pre_oci_model as model
from endpoints.api import (
    RepositoryParamResource,
    define_json_response,
    log_action,
    nickname,
    path_param,
    request_error,
    require_repo_admin,
    resource,
    validate_json_request,
)
from endpoints.exception import NotFound

logger = logging.getLogger(__name__)

# Consolidated schema definitions to avoid duplication
PERMISSION_SCHEMAS = {
    "PermissionSubjectAvatar": {
        "type": "object",
        "description": "Avatar information for a user or team.",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name associated with the avatar",
            },
            "hash": {
                "type": "string",
                "description": "Avatar hash value",
            },
            "color": {
                "type": "string",
                "description": "Color associated with the avatar",
            },
            "kind": {
                "type": "string",
                "description": "Kind of entity (user, robot, team, org)",
            },
        },
        "required": ["name", "hash", "color", "kind"],
    },
    "TeamPermission": {
        "type": "object",
        "description": "A team permission object.",
        "properties": {
            "role": {
                "type": "string",
                "enum": ["read", "write", "admin"],
                "description": "Role for the team",
            },
            "name": {
                "type": "string",
                "description": "Name of the team",
            },
            "avatar": {
                "allOf": [{"$ref": "#/definitions/PermissionSubjectAvatar"}],
                "description": "Avatar information for the team",
            },
        },
        "required": ["role", "name", "avatar"],
    },
    "UserPermission": {
        "type": "object",
        "description": "A user permission object.",
        "properties": {
            "role": {
                "type": "string",
                "enum": ["read", "write", "admin"],
                "description": "Role for the user",
            },
            "name": {
                "type": "string",
                "description": "Username",
            },
            "is_robot": {
                "type": "boolean",
                "description": "Whether the user is a robot account",
            },
            "avatar": {
                "allOf": [{"$ref": "#/definitions/PermissionSubjectAvatar"}],
                "description": "Avatar information for the user",
            },
            "is_org_member": {
                "type": "boolean",
                "description": "Whether the user is a member of the organization (only present for repositories in organizations)",
            },
        },
        "required": ["role", "name", "is_robot", "avatar"],
    },
    "PermissionRole": {
        "type": "object",
        "description": "A permission role object.",
        "properties": {
            "role": {
                "type": "string",
                "enum": ["read", "write", "admin"],
                "description": "Role for the user or team",
            },
        },
        "required": ["role"],
    },
    "TeamPermissionRequest": {
        "type": "object",
        "description": "Request body for setting team permissions.",
        "properties": {
            "role": {
                "type": "string",
                "enum": ["read", "write", "admin"],
                "description": "Role to use for the team",
            },
        },
        "required": ["role"],
    },
    "UserPermissionRequest": {
        "type": "object",
        "description": "Request body for setting user permissions.",
        "properties": {
            "role": {
                "type": "string",
                "enum": ["read", "write", "admin"],
                "description": "Role to use for the user",
            },
        },
        "required": ["role"],
    },
}


@resource("/v1/repository/<apirepopath:repository>/permissions/team/")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
class RepositoryTeamPermissionList(RepositoryParamResource):
    """
    Resource for repository team permissions.
    """

    schemas = {
        **PERMISSION_SCHEMAS,
        "TeamPermissionsDict": {
            "type": "object",
            "description": "Dictionary of team permissions keyed by team name.",
            "properties": {
                "permissions": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/definitions/TeamPermission"},
                },
            },
            "required": ["permissions"],
        },
    }

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @nickname("listRepoTeamPermissions")
    @define_json_response("TeamPermissionsDict")
    def get(self, namespace_name, repository_name):
        """
        List all team permission.
        """
        repo_perms = model.get_repo_permissions_by_team(namespace_name, repository_name)

        return {
            "permissions": {repo_perm.team_name: repo_perm.to_dict() for repo_perm in repo_perms}
        }


@resource("/v1/repository/<apirepopath:repository>/permissions/user/")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
class RepositoryUserPermissionList(RepositoryParamResource):
    """
    Resource for repository user permissions.
    """

    schemas = {
        **PERMISSION_SCHEMAS,
        "UserPermissionsDict": {
            "type": "object",
            "description": "Dictionary of user permissions keyed by username.",
            "properties": {
                "permissions": {
                    "type": "object",
                    "additionalProperties": {"$ref": "#/definitions/UserPermission"},
                },
            },
            "required": ["permissions"],
        },
    }

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @nickname("listRepoUserPermissions")
    @define_json_response("UserPermissionsDict")
    def get(self, namespace_name, repository_name):
        """
        List all user permissions.
        """
        perms = model.get_repo_permissions_by_user(namespace_name, repository_name)
        return {"permissions": {p.username: p.to_dict() for p in perms}}


@resource("/v1/repository/<apirepopath:repository>/permissions/user/<username>/transitive")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("username", "The username of the user to which the permissions apply")
class RepositoryUserTransitivePermission(RepositoryParamResource):
    """
    Resource for retrieving whether a user has access to a repository, either directly or via a
    team.
    """

    schemas = {
        **PERMISSION_SCHEMAS,
        "TransitivePermissionsList": {
            "type": "object",
            "description": "List of permission roles for a user.",
            "properties": {
                "permissions": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/PermissionRole"},
                },
            },
            "required": ["permissions"],
        },
    }

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @nickname("getUserTransitivePermission")
    @define_json_response("TransitivePermissionsList")
    def get(self, namespace_name, repository_name, username):
        """
        Get the fetch the permission for the specified user.
        """

        roles = model.get_repo_roles(username, namespace_name, repository_name)

        if not roles:
            raise NotFound

        return {"permissions": [r.to_dict() for r in roles]}


@resource("/v1/repository/<apirepopath:repository>/permissions/user/<username>")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("username", "The username of the user to which the permission applies")
class RepositoryUserPermission(RepositoryParamResource):
    """
    Resource for managing individual user permissions.
    """

    schemas = PERMISSION_SCHEMAS

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @nickname("getUserPermissions")
    @define_json_response("UserPermission")
    def get(self, namespace_name, repository_name, username):
        """
        Get the permission for the specified user.
        """
        logger.debug(
            "Get repo: %s/%s permissions for user %s", namespace_name, repository_name, username
        )
        perm = model.get_repo_permission_for_user(username, namespace_name, repository_name)
        return perm.to_dict()

    @require_repo_admin(allow_for_superuser=True)
    @nickname("changeUserPermissions")
    @validate_json_request("UserPermissionRequest")
    @define_json_response("UserPermission")
    def put(self, namespace_name, repository_name, username):  # Also needs to respond to post
        """
        Update the perimssions for an existing repository.
        """
        new_permission = request.get_json()

        logger.debug("Setting permission to: %s for user %s", new_permission["role"], username)

        try:
            perm = model.set_repo_permission_for_user(
                username, namespace_name, repository_name, new_permission["role"]
            )
            resp = perm.to_dict()
        except SaveException as ex:
            raise request_error(exception=ex)

        log_action(
            "change_repo_permission",
            namespace_name,
            {
                "username": username,
                "repo": repository_name,
                "namespace": namespace_name,
                "role": new_permission["role"],
            },
            repo_name=repository_name,
        )

        return resp, 200

    @require_repo_admin(allow_for_superuser=True)
    @nickname("deleteUserPermissions")
    def delete(self, namespace_name, repository_name, username):
        """
        Delete the permission for the user.
        """
        try:
            model.delete_repo_permission_for_user(username, namespace_name, repository_name)
        except DeleteException as ex:
            raise request_error(exception=ex)

        log_action(
            "delete_repo_permission",
            namespace_name,
            {"username": username, "repo": repository_name, "namespace": namespace_name},
            repo_name=repository_name,
        )

        return "", 204


@resource("/v1/repository/<apirepopath:repository>/permissions/team/<teamname>")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("teamname", "The name of the team to which the permission applies")
class RepositoryTeamPermission(RepositoryParamResource):
    """
    Resource for managing individual team permissions.
    """

    schemas = PERMISSION_SCHEMAS

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @nickname("getTeamPermissions")
    @define_json_response("PermissionRole")
    def get(self, namespace_name, repository_name, teamname):
        """
        Fetch the permission for the specified team.
        """
        logger.debug(
            "Get repo: %s/%s permissions for team %s", namespace_name, repository_name, teamname
        )
        role = model.get_repo_role_for_team(teamname, namespace_name, repository_name)
        return role.to_dict()

    @require_repo_admin(allow_for_superuser=True)
    @nickname("changeTeamPermissions")
    @validate_json_request("TeamPermissionRequest")
    @define_json_response("TeamPermission")
    def put(self, namespace_name, repository_name, teamname):
        """
        Update the existing team permission.
        """
        new_permission = request.get_json()

        logger.debug("Setting permission to: %s for team %s", new_permission["role"], teamname)

        try:
            perm = model.set_repo_permission_for_team(
                teamname, namespace_name, repository_name, new_permission["role"]
            )
            resp = perm.to_dict()
        except SaveException as ex:
            raise request_error(exception=ex)

        log_action(
            "change_repo_permission",
            namespace_name,
            {"team": teamname, "repo": repository_name, "role": new_permission["role"]},
            repo_name=repository_name,
        )
        return resp, 200

    @require_repo_admin(allow_for_superuser=True)
    @nickname("deleteTeamPermissions")
    def delete(self, namespace_name, repository_name, teamname):
        """
        Delete the permission for the specified team.
        """
        try:
            model.delete_repo_permission_for_team(teamname, namespace_name, repository_name)
        except DeleteException as ex:
            raise request_error(exception=ex)

        log_action(
            "delete_repo_permission",
            namespace_name,
            {"team": teamname, "repo": repository_name},
            repo_name=repository_name,
        )

        return "", 204
