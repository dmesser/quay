"""
Manage user and organization robot accounts.
"""
import json
import logging

from flask import abort, request

from auth import scopes
from auth.auth_context import get_authenticated_user
from auth.permissions import (
    AdministerOrganizationPermission,
    OrganizationMemberPermission,
)
from data.database import FederatedLogin, LoginService
from data.model import InvalidRobotException
from data.model.user import (
    attach_federated_login,
    create_federated_user,
    create_robot_federation_config,
    delete_robot_federation_config,
    get_robot_federation_config,
    lookup_robot,
)
from endpoints.api import (
    ApiResource,
    allow_if_global_readonly_superuser,
    allow_if_superuser,
    define_json_response,
    log_action,
    max_json_size,
    nickname,
    parse_args,
    path_param,
    query_param,
    related_user_resource,
    request_error,
    require_scope,
    require_user_admin,
    resource,
    validate_json_request,
)
from endpoints.api.robot_models_pre_oci import pre_oci_model as model
from endpoints.exception import Unauthorized
from util.names import format_robot_username
from util.parsing import truthy_bool

CREATE_ROBOT_SCHEMA = {
    "type": "object",
    "description": "Optional data for creating a robot",
    "properties": {
        "description": {
            "type": "string",
            "description": "Optional text description for the robot",
            "maxLength": 255,
        },
        "unstructured_metadata": {
            "type": "object",
            "description": "Optional unstructured metadata for the robot",
        },
    },
}

CREATE_ROBOT_FEDERATION_SCHEMA = {
    "type": "array",
    "description": "Federation configuration for the robot",
    "items": {
        "type": "object",
        "properties": {
            "issuer": {
                "type": "string",
                "description": "The issuer of the token",
            },
            "subject": {
                "type": "string",
                "description": "The subject of the token",
            },
        },
        "required": ["issuer", "subject"],
    },
}

# Response schemas for robot endpoints
ROBOT_RESPONSE_SCHEMAS = {
    "Robot": {
        "type": "object",
        "description": "A robot account",
        "properties": {
            "name": {
                "type": "string",
                "description": "The robot's username",
            },
            "created": {
                "type": "string",
                "description": "The date the robot was created",
                "format": "date-time",
            },
            "last_accessed": {
                "type": "string",
                "description": "The date the robot was last accessed",
                "format": "date-time",
            },
            "description": {
                "type": "string",
                "description": "The robot's description",
            },
            "token": {
                "type": "string",
                "description": "The robot's authentication token",
            },
            "unstructured_metadata": {
                "type": "object",
                "description": "Unstructured metadata for the robot",
            },
        },
        "required": ["name", "created", "last_accessed", "description"],
    },
    "RobotWithPermissions": {
        "type": "object",
        "description": "A robot account with permissions information",
        "properties": {
            "name": {
                "type": "string",
                "description": "The robot's username",
            },
            "created": {
                "type": "string",
                "description": "The date the robot was created",
                "format": "date-time",
            },
            "last_accessed": {
                "type": "string",
                "description": "The date the robot was last accessed",
                "format": "date-time",
            },
            "teams": {
                "type": "array",
                "description": "Teams the robot belongs to",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The team name",
                        },
                        "avatar": {
                            "type": "object",
                            "description": "The team's avatar information",
                        },
                    },
                    "required": ["name", "avatar"],
                },
            },
            "repositories": {
                "type": "array",
                "description": "Repository names the robot has access to",
                "items": {
                    "type": "string",
                },
            },
            "description": {
                "type": "string",
                "description": "The robot's description",
            },
            "token": {
                "type": "string",
                "description": "The robot's authentication token",
            },
        },
        "required": ["name", "created", "last_accessed", "teams", "repositories", "description"],
    },
    "RobotList": {
        "type": "object",
        "description": "List of robots",
        "properties": {
            "robots": {
                "type": "array",
                "description": "List of robot objects",
                "items": {
                    "$ref": "#/definitions/RobotWithPermissions",
                },
            },
        },
        "required": ["robots"],
    },
    "Permission": {
        "type": "object",
        "description": "A robot's permission on a repository",
        "properties": {
            "repository": {
                "type": "object",
                "description": "Repository information",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The repository name",
                    },
                    "is_public": {
                        "type": "boolean",
                        "description": "Whether the repository is public",
                    },
                },
                "required": ["name", "is_public"],
            },
            "role": {
                "type": "string",
                "description": "The role the robot has on the repository",
                "enum": ["read", "write", "admin"],
            },
        },
        "required": ["repository", "role"],
    },
    "PermissionList": {
        "type": "object",
        "description": "List of robot permissions",
        "properties": {
            "permissions": {
                "type": "array",
                "description": "List of permission objects",
                "items": {
                    "$ref": "#/definitions/Permission",
                },
            },
        },
        "required": ["permissions"],
    },
    "ErrorResponse": {
        "type": "object",
        "description": "Error response",
        "properties": {
            "message": {
                "type": "string",
                "description": "Error message",
            },
        },
        "required": ["message"],
    },
}

ROBOT_MAX_SIZE = 1024 * 1024  # 1 KB.

logger = logging.getLogger(__name__)


def robots_list(prefix, include_permissions=False, include_token=False, limit=None):
    robots = model.list_entity_robot_permission_teams(
        prefix, limit=limit, include_token=include_token, include_permissions=include_permissions
    )
    return {"robots": [robot.to_dict(include_token=include_token) for robot in robots]}


@resource("/v1/user/robots")
class UserRobotList(ApiResource):
    """
    Resource for listing user robots.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_user_admin()
    @nickname("getUserRobots")
    @parse_args()
    @query_param(
        "permissions",
        "Whether to include repositories and teams in which the robots have permission.",
        type=truthy_bool,
        default=False,
    )
    @query_param(
        "token", "If false, the robot's token is not returned.", type=truthy_bool, default=True
    )
    @query_param("limit", "If specified, the number of robots to return.", type=int, default=None)
    @define_json_response("RobotList")
    def get(self, parsed_args):
        """
        List the available robots for the user.
        """
        user = get_authenticated_user()
        return robots_list(
            user.username,
            include_token=parsed_args.get("token", True),
            include_permissions=parsed_args.get("permissions", False),
            limit=parsed_args.get("limit"),
        )


@resource("/v1/user/robots/<robot_shortname>")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
class UserRobot(ApiResource):
    """
    Resource for managing a user's robots.
    """

    schemas = {
        "CreateRobot": CREATE_ROBOT_SCHEMA,
        **ROBOT_RESPONSE_SCHEMAS,
    }

    @require_user_admin()
    @nickname("getUserRobot")
    @define_json_response("Robot")
    def get(self, robot_shortname):
        """
        Returns the user's robot with the specified name.
        """
        parent = get_authenticated_user()
        robot = model.get_user_robot(robot_shortname, parent)
        return robot.to_dict(include_metadata=True, include_token=True)

    @require_user_admin(disallow_for_restricted_users=True)
    @nickname("createUserRobot")
    @max_json_size(ROBOT_MAX_SIZE)
    @validate_json_request("CreateRobot", optional=True)
    @define_json_response("Robot")
    def put(self, robot_shortname):
        """
        Create a new user robot with the specified name.
        """
        parent = get_authenticated_user()
        create_data = request.get_json(silent=True) or {}

        try:
            robot = model.create_user_robot(
                robot_shortname,
                parent,
                create_data.get("description"),
                create_data.get("unstructured_metadata"),
            )
        except InvalidRobotException as e:
            raise request_error(message=str(e))
        log_action(
            "create_robot",
            parent.username,
            {
                "robot": robot_shortname,
                "description": create_data.get("description"),
                "unstructured_metadata": create_data.get("unstructured_metadata"),
            },
        )
        return robot.to_dict(include_metadata=True, include_token=True), 201

    @require_user_admin(disallow_for_restricted_users=True)
    @nickname("deleteUserRobot")
    def delete(self, robot_shortname):
        """
        Delete an existing robot.
        """
        parent = get_authenticated_user()
        robot_username = format_robot_username(parent.username, robot_shortname)

        if not model.robot_has_mirror(robot_username):
            model.delete_robot(robot_username)
            log_action("delete_robot", parent.username, {"robot": robot_shortname})
            return "", 204
        else:
            raise request_error(message="Robot is being used by a mirror")


@resource("/v1/organization/<orgname>/robots")
@path_param("orgname", "The name of the organization")
@related_user_resource(UserRobotList)
class OrgRobotList(ApiResource):
    """
    Resource for listing an organization's robots.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_scope(scopes.ORG_ADMIN)
    @nickname("getOrgRobots")
    @parse_args()
    @query_param(
        "permissions",
        "Whether to include repostories and teams in which the robots have permission.",
        type=truthy_bool,
        default=False,
    )
    @query_param(
        "token", "If false, the robot's token is not returned.", type=truthy_bool, default=True
    )
    @query_param("limit", "If specified, the number of robots to return.", type=int, default=None)
    @define_json_response("RobotList")
    def get(self, orgname, parsed_args):
        """
        List the organization's robots.
        """
        permission = OrganizationMemberPermission(orgname)
        if permission.can() or allow_if_superuser() or allow_if_global_readonly_superuser():
            include_token = (
                AdministerOrganizationPermission(orgname).can()
                or allow_if_global_readonly_superuser()
            ) and parsed_args.get("token", True)
            include_permissions = AdministerOrganizationPermission(
                orgname
            ).can() and parsed_args.get("permissions", False)
            return robots_list(
                orgname,
                include_permissions=include_permissions,
                include_token=include_token,
                limit=parsed_args.get("limit"),
            )

        raise Unauthorized()


@resource("/v1/organization/<orgname>/robots/<robot_shortname>")
@path_param("orgname", "The name of the organization")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
@related_user_resource(UserRobot)
class OrgRobot(ApiResource):
    """
    Resource for managing an organization's robots.
    """

    schemas = {
        "CreateRobot": CREATE_ROBOT_SCHEMA,
        **ROBOT_RESPONSE_SCHEMAS,
    }

    @require_scope(scopes.ORG_ADMIN)
    @nickname("getOrgRobot")
    @define_json_response("Robot")
    def get(self, orgname, robot_shortname):
        """
        Returns the organization's robot with the specified name.
        """
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser() or allow_if_global_readonly_superuser():
            robot = model.get_org_robot(robot_shortname, orgname)
            return robot.to_dict(include_metadata=True, include_token=True)

        raise Unauthorized()

    @require_scope(scopes.ORG_ADMIN)
    @nickname("createOrgRobot")
    @max_json_size(ROBOT_MAX_SIZE)
    @validate_json_request("CreateRobot", optional=True)
    @define_json_response("Robot")
    def put(self, orgname, robot_shortname):
        """
        Create a new robot in the organization.
        """
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser():
            create_data = request.get_json(silent=True) or {}

            try:
                robot = model.create_org_robot(
                    robot_shortname,
                    orgname,
                    create_data.get("description"),
                    create_data.get("unstructured_metadata"),
                )
            except InvalidRobotException as e:
                raise request_error(message=str(e))
            log_action(
                "create_robot",
                orgname,
                {
                    "robot": robot_shortname,
                    "description": create_data.get("description"),
                    "unstructured_metadata": create_data.get("unstructured_metadata"),
                },
            )
            return robot.to_dict(include_metadata=True, include_token=True), 201

        raise Unauthorized()

    @require_scope(scopes.ORG_ADMIN)
    @nickname("deleteOrgRobot")
    def delete(self, orgname, robot_shortname):
        """
        Delete an existing organization robot.
        """
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser():
            robot_username = format_robot_username(orgname, robot_shortname)
            if not model.robot_has_mirror(robot_username):
                model.delete_robot(robot_username)
                log_action("delete_robot", orgname, {"robot": robot_shortname})
                return "", 204
            else:
                raise request_error(message="Robot is being used by a mirror")

        raise Unauthorized()


@resource("/v1/user/robots/<robot_shortname>/permissions")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
class UserRobotPermissions(ApiResource):
    """
    Resource for listing the permissions a user's robot has in the system.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_user_admin()
    @nickname("getUserRobotPermissions")
    @define_json_response("PermissionList")
    def get(self, robot_shortname):
        """
        Returns the list of repository permissions for the user's robot.
        """
        parent = get_authenticated_user()
        robot = model.get_user_robot(robot_shortname, parent)
        permissions = model.list_robot_permissions(robot.name)

        return {"permissions": [permission.to_dict() for permission in permissions]}


@resource("/v1/organization/<orgname>/robots/<robot_shortname>/permissions")
@path_param("orgname", "The name of the organization")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
@related_user_resource(UserRobotPermissions)
class OrgRobotPermissions(ApiResource):
    """
    Resource for listing the permissions an org's robot has in the system.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_user_admin()
    @nickname("getOrgRobotPermissions")
    @define_json_response("PermissionList")
    def get(self, orgname, robot_shortname):
        """
        Returns the list of repository permissions for the org's robot.
        """
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser() or allow_if_global_readonly_superuser():
            robot = model.get_org_robot(robot_shortname, orgname)
            permissions = model.list_robot_permissions(robot.name)

            return {"permissions": [permission.to_dict() for permission in permissions]}

        abort(403)


@resource("/v1/user/robots/<robot_shortname>/regenerate")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
class RegenerateUserRobot(ApiResource):
    """
    Resource for regenerate an organization's robot's token.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_user_admin(disallow_for_restricted_users=True)
    @nickname("regenerateUserRobotToken")
    @define_json_response("Robot")
    def post(self, robot_shortname):
        """
        Regenerates the token for a user's robot.
        """
        parent = get_authenticated_user()
        robot = model.regenerate_user_robot_token(robot_shortname, parent)
        log_action("regenerate_robot_token", parent.username, {"robot": robot_shortname})
        return robot.to_dict(include_token=True)


@resource("/v1/organization/<orgname>/robots/<robot_shortname>/regenerate")
@path_param("orgname", "The name of the organization")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
@related_user_resource(RegenerateUserRobot)
class RegenerateOrgRobot(ApiResource):
    """
    Resource for regenerate an organization's robot's token.
    """

    schemas = ROBOT_RESPONSE_SCHEMAS

    @require_scope(scopes.ORG_ADMIN)
    @nickname("regenerateOrgRobotToken")
    @define_json_response("Robot")
    def post(self, orgname, robot_shortname):
        """
        Regenerates the token for an organization robot.
        """
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser():
            robot = model.regenerate_org_robot_token(robot_shortname, orgname)
            log_action("regenerate_robot_token", orgname, {"robot": robot_shortname})
            return robot.to_dict(include_token=True)

        raise Unauthorized()


@resource("/v1/organization/<orgname>/robots/<robot_shortname>/federation")
@path_param("orgname", "The name of the organization")
@path_param(
    "robot_shortname", "The short name for the robot, without any user or organization prefix"
)
@related_user_resource(UserRobot)
class OrgRobotFederation(ApiResource):

    schemas = {
        "CreateRobotFederation": CREATE_ROBOT_FEDERATION_SCHEMA,
        "RobotFederationConfig": {
            "type": "array",
            "description": "Federation configuration for the robot",
            "items": {
                "type": "object",
                "properties": {
                    "issuer": {
                        "type": "string",
                        "description": "The issuer of the token",
                    },
                    "subject": {
                        "type": "string",
                        "description": "The subject of the token",
                    },
                },
                "required": ["issuer", "subject"],
            },
        },
    }

    @require_scope(scopes.ORG_ADMIN)
    @nickname("getOrgRobotFederation")
    @define_json_response("RobotFederationConfig")
    def get(self, orgname, robot_shortname):
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser() or allow_if_global_readonly_superuser():
            robot_username = format_robot_username(orgname, robot_shortname)
            robot = lookup_robot(robot_username)
            return get_robot_federation_config(robot)

        raise Unauthorized()

    @require_scope(scopes.ORG_ADMIN)
    @nickname("createOrgRobotFederation")
    @validate_json_request("CreateRobotFederation", optional=False)
    @define_json_response("RobotFederationConfig")
    def post(self, orgname, robot_shortname):
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser():
            fed_config = self._parse_federation_config(request)

            robot_username = format_robot_username(orgname, robot_shortname)
            robot = lookup_robot(robot_username)
            create_robot_federation_config(robot, fed_config)
            log_action(
                "create_robot_federation",
                orgname,
                {"config": fed_config, "robot": robot_shortname},
            )
            return fed_config

        raise Unauthorized()

    @require_scope(scopes.ORG_ADMIN)
    @nickname("deleteOrgRobotFederation")
    def delete(self, orgname, robot_shortname):
        permission = AdministerOrganizationPermission(orgname)
        if permission.can() or allow_if_superuser():
            robot_username = format_robot_username(orgname, robot_shortname)
            robot = lookup_robot(robot_username)
            delete_robot_federation_config(robot)
            log_action(
                "delete_robot_federation",
                orgname,
                {"robot": robot_shortname},
            )
            return "", 204
        raise Unauthorized()

    def _parse_federation_config(self, request):
        fed_config = list()
        seen = set()
        for item in request.json:
            if not item:
                raise request_error(message="Missing one or more required fields (issuer, subject)")
            issuer = item.get("issuer")
            subject = item.get("subject")
            if not issuer or not subject:
                raise request_error(message="Missing one or more required fields (issuer, subject)")
            if not (issuer.startswith("http://") or issuer.startswith("https://")):
                raise request_error(message="Issuer must be a URL (http:// or https://)")
            entry = {"issuer": issuer, "subject": subject}

            if f"{issuer}:{subject}" in seen:
                raise request_error(message="Duplicate federation config entry")

            seen.add(f"{issuer}:{subject}")
            fed_config.append(entry)

        return list(fed_config)
