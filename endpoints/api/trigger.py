"""
Create, list and manage build triggers.
"""

import logging
from urllib.parse import urlunparse

from flask import request, url_for

from app import app
from auth.auth_context import get_authenticated_user
from auth.permissions import (
    AdministerOrganizationPermission,
    AdministerRepositoryPermission,
    UserAdminPermission,
)
from buildtrigger.basehandler import BuildTriggerHandler
from buildtrigger.triggerutil import EmptyRepositoryException, TriggerException
from data import model
from data.fields import DecryptedValue
from data.model.build import update_build_trigger
from endpoints.api import (
    RepositoryParamResource,
    abort,
    allow_if_superuser,
    api,
    define_json_response,
    disallow_for_app_repositories,
    disallow_for_non_normal_repositories,
    disallow_for_user_namespace,
    internal_only,
    log_action,
    nickname,
    parse_args,
    path_param,
    query_param,
    request_error,
    require_repo_admin,
    resource,
    validate_json_request,
)
from endpoints.api.build import RepositoryBuildStatus, build_status_view, trigger_view
from endpoints.api.trigger_analyzer import TriggerAnalyzer
from endpoints.building import (
    BuildTriggerDisabledException,
    MaximumBuildsQueuedException,
    start_build,
)
from endpoints.exception import InvalidRequest, NotFound, Unauthorized
from util.names import parse_robot_username

logger = logging.getLogger(__name__)


def _prepare_webhook_url(scheme, username, password, hostname, path):
    auth_hostname = "%s:%s@%s" % (username, password, hostname)
    return urlunparse((scheme, auth_hostname, path, "", "", ""))


def get_trigger(trigger_uuid):
    try:
        trigger = model.build.get_build_trigger(trigger_uuid)
    except model.InvalidBuildTriggerException:
        raise NotFound()
    return trigger


# Response schemas for build trigger endpoints
TRIGGER_RESPONSE_SCHEMAS = {
    "TriggerView": {
        "type": "object",
        "description": "Information about a build trigger",
        "properties": {
            "id": {
                "type": "string",
                "description": "The unique identifier for the trigger",
            },
            "service": {
                "type": "string",
                "description": "The service name (e.g., 'github', 'gitlab')",
            },
            "is_active": {
                "type": "boolean",
                "description": "Whether the trigger is currently active",
            },
            "build_source": {
                "type": ["string", "null"],
                "description": "The source branch or tag for the build",
                "x-nullable": True,
            },
            "repository_url": {
                "type": ["string", "null"],
                "description": "The URL of the source repository",
                "x-nullable": True,
            },
            "config": {
                "type": "object",
                "description": "The trigger configuration (only visible to admins)",
            },
            "can_invoke": {
                "type": "boolean",
                "description": "Whether the user can manually invoke this trigger",
            },
            "enabled": {
                "type": "boolean",
                "description": "Whether the trigger is enabled",
            },
            "disabled_reason": {
                "type": ["string", "null"],
                "description": "Reason why the trigger is disabled, if applicable",
                "x-nullable": True,
            },
            "pull_robot": {
                "type": "object",
                "description": "The robot account used for pulling images (only included for admins)",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The username of the robot",
                    },
                    "kind": {
                        "type": "string",
                        "description": "The type of account",
                    },
                    "is_robot": {
                        "type": "boolean",
                        "description": "Whether this is a robot account",
                    },
                },
                "required": ["name", "kind", "is_robot"],
            },
        },
        "required": ["id", "service", "is_active", "can_invoke", "enabled"],
    },
    "TriggerListResponse": {
        "type": "object",
        "description": "Response containing a list of build triggers",
        "properties": {
            "triggers": {
                "type": "array",
                "description": "List of build triggers",
                "items": {"allOf": [{"$ref": "#/definitions/TriggerView"}]},
            },
        },
        "required": ["triggers"],
    },
    "BuildStatusView": {
        "type": "object",
        "description": "Information about a build status",
        "properties": {
            "id": {
                "type": "string",
                "description": "Build ID",
            },
            "phase": {
                "type": "string",
                "description": "Build phase",
            },
            "started": {
                "type": "string",
                "description": "Start time (RFC 2822 format)",
            },
            "display_name": {
                "type": "string",
                "description": "Display name",
            },
            "status": {
                "type": "object",
                "description": "Build status",
            },
            "subdirectory": {
                "type": "string",
                "description": "Build subdirectory",
            },
            "dockerfile_path": {
                "type": "string",
                "description": "Dockerfile path",
            },
            "context": {
                "type": "string",
                "description": "Build context",
            },
            "tags": {
                "type": "array",
                "description": "Docker tags",
                "items": {
                    "type": "string",
                },
            },
            "manual_user": {
                "type": ["string", "null"],
                "description": "Manual user",
                "x-nullable": True,
            },
            "is_writer": {
                "type": "boolean",
                "description": "Whether user can write",
            },
            "trigger": {
                "type": ["object", "null"],
                "description": "The build trigger that started this build",
                "x-nullable": True,
                "properties": {
                    "id": {"type": "string"},
                    "service": {"type": "string"},
                    "is_active": {"type": "boolean"},
                    "build_source": {"type": ["string", "null"], "x-nullable": True},
                    "repository_url": {"type": ["string", "null"], "x-nullable": True},
                    "config": {"type": "object"},
                    "can_invoke": {"type": "boolean"},
                    "enabled": {"type": "boolean"},
                    "disabled_reason": {"type": ["string", "null"], "x-nullable": True},
                },
            },
            "trigger_metadata": {
                "type": ["object", "null"],
                "description": "Trigger metadata",
                "x-nullable": True,
            },
            "resource_key": {
                "type": ["string", "null"],
                "description": "Resource key",
                "x-nullable": True,
            },
            "pull_robot": {
                "type": ["object", "null"],
                "description": "The robot account used for pulling images",
                "x-nullable": True,
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The username of the robot",
                    },
                    "kind": {
                        "type": "string",
                        "description": "The type of account",
                    },
                    "is_robot": {
                        "type": "boolean",
                        "description": "Whether this is a robot account",
                    },
                },
            },
            "repository": {
                "type": "object",
                "description": "Repository information",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Repository namespace",
                    },
                    "name": {
                        "type": "string",
                        "description": "Repository name",
                    },
                },
                "required": ["namespace", "name"],
            },
            "error": {
                "type": ["string", "null"],
                "description": "Error message",
                "x-nullable": True,
            },
            "archive_url": {
                "type": "string",
                "description": "Archive URL (only included if user has write permissions or READER_BUILD_LOGS is enabled)",
            },
        },
        "required": [
            "id",
            "phase",
            "started",
            "display_name",
            "status",
            "subdirectory",
            "dockerfile_path",
            "context",
            "tags",
            "is_writer",
            "repository",
        ],
    },
    "BuildListResponse": {
        "type": "object",
        "description": "Response containing a list of builds",
        "properties": {
            "builds": {
                "type": "array",
                "description": "List of builds",
                "items": {"allOf": [{"$ref": "#/definitions/BuildStatusView"}]},
            },
        },
        "required": ["builds"],
    },
    "SubdirsResponse": {
        "type": "object",
        "description": "Response containing buildable subdirectories",
        "properties": {
            "dockerfile_paths": {
                "type": "array",
                "description": "List of Dockerfile paths (only included on success). Note: Paths are normalized by prepending '/', which creates double slashes for Bitbucket paths",
                "items": {
                    "type": "string",
                    "pattern": "^/",
                    "description": "Dockerfile path starting with '/' (Bitbucket paths may have '//' due to normalization bug)",
                },
            },
            "contextMap": {
                "type": "object",
                "description": "Context mapping information (only included on success)",
                "additionalProperties": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "description": "Possible context paths for the Dockerfile",
                    },
                },
            },
            "status": {
                "type": "string",
                "description": "Status of the operation",
                "enum": ["success", "error"],
            },
            "message": {
                "type": "string",
                "description": "Error message (only included if status is error)",
            },
        },
        "required": ["status"],
    },
    "AnalysisResponse": {
        "type": "object",
        "description": "Response containing trigger analysis",
        "properties": {
            "status": {
                "type": "string",
                "description": "Analysis status",
                "enum": [
                    "analyzed",
                    "error",
                    "notimplemented",
                    "warning",
                    "publicbase",
                    "requiresrobot",
                ],
            },
            "message": {
                "type": ["string", "null"],
                "description": "Error or warning message (only included for error/warning status)",
                "x-nullable": True,
            },
            "namespace": {
                "type": ["string", "null"],
                "description": "Image namespace",
                "x-nullable": True,
            },
            "name": {
                "type": ["string", "null"],
                "description": "Image repository name",
                "x-nullable": True,
            },
            "robots": {
                "type": "array",
                "description": "List of available robot accounts (only included for admins)",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Robot username",
                        },
                        "kind": {
                            "type": "string",
                            "description": "Account type",
                        },
                        "is_robot": {
                            "type": "boolean",
                            "description": "Whether this is a robot account",
                        },
                        "can_read": {
                            "type": "boolean",
                            "description": "Whether the robot has read access",
                        },
                    },
                    "required": ["name", "kind", "is_robot", "can_read"],
                },
            },
            "is_admin": {
                "type": "boolean",
                "description": "Whether the user has admin permissions",
            },
        },
        "required": ["status"],
    },
    "FieldValueItem": {
        "type": "object",
        "description": "A field value item which can be either a string or a ref object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["branch", "tag"],
                "description": "Type of ref (only present for ref objects)",
            },
            "name": {
                "type": "string",
                "description": "Name of the branch or tag (for ref objects) or the value itself (for string values)",
            },
        },
        "required": ["name"],
    },
    "FieldValuesResponse": {
        "type": "object",
        "description": "Response containing field values. The format depends on the field_name and handler type: for branch_name/tag_name fields, values are strings; for refs field, values are objects with kind and name properties.",
        "properties": {
            "values": {
                "type": "array",
                "description": "List of field values. Items can be either strings (for branch_name/tag_name fields) or objects with 'kind' and 'name' properties (for refs field).",
                "items": {
                    "type": ["string", "object", "integer"],
                    "additionalProperties": True,
                },
            },
        },
        "required": ["values"],
    },
    "SourceItem": {
        "type": "object",
        "description": "Source repository information",
        "properties": {
            "name": {
                "type": ["string", "null"],
                "description": "Repository name (GitHub), project path (GitLab), or repository slug (Bitbucket)",
                "x-nullable": True,
            },
            "full_name": {
                "type": ["string", "null"],
                "description": "Full repository name with owner/namespace",
                "x-nullable": True,
            },
            "description": {
                "type": ["string", "null"],
                "description": "Repository/project description (empty string if none)",
                "x-nullable": True,
            },
            "last_updated": {
                "type": ["integer", "null"],
                "description": "Last update timestamp (0 if no push date for GitHub; may be omitted for GitLab if invalid)",
                "x-nullable": True,
            },
            "url": {
                "type": ["string", "null"],
                "description": "Repository/project URL",
                "x-nullable": True,
            },
            "has_admin_permissions": {
                "type": ["boolean", "null"],
                "description": "Whether user has admin permissions (always true for GitHub; based on access level for GitLab; based on read_only flag for Bitbucket)",
                "x-nullable": True,
            },
            "private": {
                "type": ["boolean", "null"],
                "description": "Whether repository/project is private",
                "x-nullable": True,
            },
        },
    },
    "SourcesResponse": {
        "type": "object",
        "description": "Response containing build sources. The exact fields and their semantics vary by handler type (GitHub, GitLab, Bitbucket).",
        "properties": {
            "sources": {
                "type": "array",
                "description": "List of source repositories/projects",
                "items": {"allOf": [{"$ref": "#/definitions/SourceItem"}]},
            },
        },
        "required": ["sources"],
    },
    "NamespaceItem": {
        "type": "object",
        "description": "Namespace information",
        "properties": {
            "id": {
                "type": ["string", "null"],
                "description": "Namespace identifier (username/org for GitHub, numeric ID for GitLab, owner name for Bitbucket)",
                "x-nullable": True,
            },
            "title": {
                "type": ["string", "null"],
                "description": "Display name",
                "x-nullable": True,
            },
            "personal": {
                "type": ["boolean", "null"],
                "description": "True if this is a personal namespace",
                "x-nullable": True,
            },
            "avatar_url": {
                "type": ["string", "null"],
                "description": "Avatar/logo URL",
                "x-nullable": True,
            },
            "url": {
                "type": ["string", "null"],
                "description": "Profile URL (may be empty for GitHub organizations)",
                "x-nullable": True,
            },
            "score": {
                "type": ["integer", "null"],
                "description": "Relevance score (repo count or similar metric)",
                "x-nullable": True,
            },
        },
    },
    "NamespacesResponse": {
        "type": "object",
        "description": "Response containing namespace information. The exact semantics vary by handler type (GitHub, GitLab, Bitbucket).",
        "properties": {
            "namespaces": {
                "type": "array",
                "description": "List of namespaces",
                "items": {"allOf": [{"$ref": "#/definitions/NamespaceItem"}]},
            },
        },
        "required": ["namespaces"],
    },
}


@resource("/v1/repository/<apirepopath:repository>/trigger/")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
class BuildTriggerList(RepositoryParamResource):
    """
    Resource for listing repository build triggers.
    """

    schemas = TRIGGER_RESPONSE_SCHEMAS

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @disallow_for_app_repositories
    @nickname("listBuildTriggers")
    @define_json_response("TriggerListResponse")
    def get(self, namespace_name, repo_name):
        """
        List the triggers for the specified repository.
        """
        triggers = model.build.list_build_triggers(namespace_name, repo_name)
        return {"triggers": [trigger_view(trigger, can_admin=True) for trigger in triggers]}


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
class BuildTrigger(RepositoryParamResource):
    """
    Resource for managing specific build triggers.
    """

    schemas = {
        "UpdateTrigger": {
            "type": "object",
            "description": "Options for updating a build trigger",
            "required": [
                "enabled",
            ],
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "description": "Whether the build trigger is enabled",
                },
            },
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @disallow_for_app_repositories
    @nickname("getBuildTrigger")
    @define_json_response("TriggerView")
    def get(self, namespace_name, repo_name, trigger_uuid):
        """
        Get information for the specified build trigger.
        """
        return trigger_view(get_trigger(trigger_uuid), can_admin=True)

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("updateBuildTrigger")
    @validate_json_request("UpdateTrigger")
    @define_json_response("TriggerView")
    def put(self, namespace_name, repo_name, trigger_uuid):
        """
        Updates the specified build trigger.
        """
        trigger = get_trigger(trigger_uuid)

        handler = BuildTriggerHandler.get_handler(trigger)
        if not handler.is_active():
            raise InvalidRequest("Cannot update an unactivated trigger")

        enable = request.get_json()["enabled"]
        model.build.toggle_build_trigger(trigger, enable)
        log_action(
            "toggle_repo_trigger",
            namespace_name,
            {
                "repo": repo_name,
                "trigger_id": trigger_uuid,
                "service": trigger.service.name,
                "enabled": enable,
            },
            repo=model.repository.get_repository(namespace_name, repo_name),
        )

        return trigger_view(trigger)

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("deleteBuildTrigger")
    def delete(self, namespace_name, repo_name, trigger_uuid):
        """
        Delete the specified build trigger.
        """
        trigger = get_trigger(trigger_uuid)

        handler = BuildTriggerHandler.get_handler(trigger)
        if handler.is_active():
            try:
                handler.deactivate()
            except TriggerException as ex:
                # We are just going to eat this error
                logger.warning("Trigger deactivation problem: %s", ex)

            log_action(
                "delete_repo_trigger",
                namespace_name,
                {"repo": repo_name, "trigger_id": trigger_uuid, "service": trigger.service.name},
                repo=model.repository.get_repository(namespace_name, repo_name),
            )

        trigger.delete_instance(recursive=True)

        if trigger.write_token is not None:
            trigger.write_token.delete_instance()

        return "No Content", 204


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/subdir")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
@internal_only
class BuildTriggerSubdirs(RepositoryParamResource):
    """
    Custom verb for fetching the subdirs which are buildable for a trigger.

    Note: Handler implementations return paths differently:
    - GitHub: Returns paths like "Dockerfile", "somesubdir/Dockerfile" (no leading slash)
    - GitLab: Returns just filenames like "Dockerfile" (not full paths)
    - Bitbucket: Returns paths like "/Dockerfile" (with leading slash)
    - Custom handler: always returns 404 Not Found (NotImplementedError)

    The endpoint normalizes by prepending "/" to all paths, which causes Bitbucket paths
    to have double slashes (e.g., "//Dockerfile").
    """

    schemas = {
        "BuildTriggerSubdirRequest": {
            "type": "object",
            "description": "Arbitrary json.",
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("listBuildTriggerSubdirs")
    @validate_json_request("BuildTriggerSubdirRequest")
    @define_json_response("SubdirsResponse")
    def post(self, namespace_name, repo_name, trigger_uuid):
        """
        List the subdirectories available for the specified build trigger and source.
        """
        trigger = get_trigger(trigger_uuid)

        user_permission = UserAdminPermission(trigger.connected_user.username)
        if user_permission.can():
            new_config_dict = request.get_json()
            handler = BuildTriggerHandler.get_handler(trigger, new_config_dict)

            try:
                subdirs = handler.list_build_subdirs()
                context_map = {}
                for file in subdirs:
                    context_map = handler.get_parent_directory_mappings(file, context_map)

                return {
                    "dockerfile_paths": ["/" + subdir for subdir in subdirs],
                    "contextMap": context_map,
                    "status": "success",
                }
            except EmptyRepositoryException as exc:
                return {
                    "status": "success",
                    "contextMap": {},
                    "dockerfile_paths": [],
                }
            except TriggerException as exc:
                return {
                    "status": "error",
                    "message": str(exc),
                }
        else:
            raise Unauthorized()


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/activate")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
class BuildTriggerActivate(RepositoryParamResource):
    """
    Custom verb for activating a build trigger once all required information has been collected.
    """

    schemas = {
        "BuildTriggerActivateRequest": {
            "type": "object",
            "required": ["config"],
            "properties": {
                "config": {
                    "type": "object",
                    "description": "Arbitrary json.",
                },
                "pull_robot": {
                    "type": "string",
                    "description": "The name of the robot that will be used to pull images.",
                },
            },
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("activateBuildTrigger")
    @validate_json_request("BuildTriggerActivateRequest")
    @define_json_response("TriggerView")
    def post(self, namespace_name, repo_name, trigger_uuid):
        """
        Activate the specified build trigger.
        """
        trigger = get_trigger(trigger_uuid)
        handler = BuildTriggerHandler.get_handler(trigger)
        if handler.is_active():
            raise InvalidRequest("Trigger config is not sufficient for activation.")

        user_permission = UserAdminPermission(trigger.connected_user.username)
        if user_permission.can() or allow_if_superuser():
            # Update the pull robot (if any).
            pull_robot_name = request.get_json().get("pull_robot", None)
            if pull_robot_name:
                try:
                    pull_robot = model.user.lookup_robot(pull_robot_name)
                except model.InvalidRobotException:
                    raise NotFound()

                # Make sure the user has administer permissions for the robot's namespace.
                (robot_namespace, _) = parse_robot_username(pull_robot_name)
                if not AdministerOrganizationPermission(robot_namespace).can():
                    raise Unauthorized()

                # Make sure the namespace matches that of the trigger.
                if robot_namespace != namespace_name:
                    raise Unauthorized()

                # Set the pull robot.
                trigger.pull_robot = pull_robot

            # Update the config.
            new_config_dict = request.get_json()["config"]

            write_token_name = "Build Trigger: %s" % trigger.service.name
            write_token = model.token.create_delegate_token(
                namespace_name, repo_name, write_token_name, "write"
            )

            try:
                path = url_for("webhooks.build_trigger_webhook", trigger_uuid=trigger.uuid)
                authed_url = _prepare_webhook_url(
                    app.config["PREFERRED_URL_SCHEME"],
                    "$token",
                    write_token.get_code(),
                    app.config["SERVER_HOSTNAME"],
                    path,
                )

                handler = BuildTriggerHandler.get_handler(trigger, new_config_dict)
                final_config, private_config = handler.activate(authed_url)

                if "private_key" in private_config:
                    trigger.secure_private_key = DecryptedValue(private_config["private_key"])

            except TriggerException as exc:
                write_token.delete_instance()
                raise request_error(message=str(exc))

            # Save the updated config.
            update_build_trigger(trigger, final_config, write_token=write_token)

            # Log the trigger setup.
            repo = model.repository.get_repository(namespace_name, repo_name)
            log_action(
                "setup_repo_trigger",
                namespace_name,
                {
                    "repo": repo_name,
                    "namespace": namespace_name,
                    "trigger_id": trigger.uuid,
                    "service": trigger.service.name,
                    "pull_robot": trigger.pull_robot.username if trigger.pull_robot else None,
                    "config": final_config,
                },
                repo=repo,
            )

            return trigger_view(trigger, can_admin=True)
        else:
            raise Unauthorized()


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/analyze")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
@internal_only
class BuildTriggerAnalyze(RepositoryParamResource):
    """
    Custom verb for analyzing the config for a build trigger and suggesting various changes (such as
    a robot account to use for pulling)
    """

    schemas = {
        "BuildTriggerAnalyzeRequest": {
            "type": "object",
            "required": ["config"],
            "properties": {
                "config": {
                    "type": "object",
                    "description": "Arbitrary json.",
                }
            },
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("analyzeBuildTrigger")
    @validate_json_request("BuildTriggerAnalyzeRequest")
    @define_json_response("AnalysisResponse")
    def post(self, namespace_name, repo_name, trigger_uuid):
        """
        Analyze the specified build trigger configuration.
        """
        trigger = get_trigger(trigger_uuid)

        if trigger.repository.namespace_user.username != namespace_name:
            raise NotFound()

        if trigger.repository.name != repo_name:
            raise NotFound()

        new_config_dict = request.get_json()["config"]
        handler = BuildTriggerHandler.get_handler(trigger, new_config_dict)
        server_hostname = app.config["SERVER_HOSTNAME"]
        try:
            trigger_analyzer = TriggerAnalyzer(
                handler,
                namespace_name,
                server_hostname,
                new_config_dict,
                AdministerOrganizationPermission(namespace_name).can(),
            )
            return trigger_analyzer.analyze_trigger()
        except TriggerException as rre:
            return {
                "status": "error",
                "message": "Could not analyze the repository: %s" % rre,
            }
        except NotImplementedError:
            return {
                "status": "notimplemented",
            }


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/start")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
class ActivateBuildTrigger(RepositoryParamResource):
    """
    Custom verb to manually activate a build trigger.
    """

    schemas = {
        "RunParameters": {
            "type": "object",
            "description": "Optional run parameters for activating the build trigger",
            "properties": {
                "branch_name": {
                    "type": "string",
                    "description": "(SCM only) If specified, the name of the branch to build.",
                },
                "commit_sha": {
                    "type": "string",
                    "description": "(Custom Only) If specified, the ref/SHA1 used to checkout a git repository.",
                },
                "refs": {
                    "type": ["object", "null"],
                    "description": "(SCM Only) If specified, the ref to build.",
                },
            },
            "additionalProperties": False,
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("manuallyStartBuildTrigger")
    @validate_json_request("RunParameters")
    @define_json_response("BuildStatusView")
    def post(self, namespace_name, repo_name, trigger_uuid):
        """
        Manually start a build from the specified trigger.
        """
        trigger = get_trigger(trigger_uuid)
        if not trigger.enabled:
            raise InvalidRequest("Trigger is not enabled.")

        handler = BuildTriggerHandler.get_handler(trigger)
        if not handler.is_active():
            raise InvalidRequest("Trigger is not active.")

        try:
            repo = model.repository.get_repository(namespace_name, repo_name)
            pull_robot_name = model.build.get_pull_robot_name(trigger)

            run_parameters = request.get_json()
            prepared = handler.manual_start(run_parameters=run_parameters)
            performer = get_authenticated_user()
            build_request = start_build(
                repo,
                prepared,
                pull_robot_name=pull_robot_name,
                performer=performer,
                manual_trigger=True,
            )
        except TriggerException as tse:
            raise InvalidRequest(str(tse)) from tse
        except MaximumBuildsQueuedException:
            abort(429, message="Maximum queued build rate exceeded.")
        except BuildTriggerDisabledException:
            abort(400, message="Build trigger is disabled")

        resp = build_status_view(build_request)
        repo_string = "%s/%s" % (namespace_name, repo_name)
        headers = {
            "Location": api.url_for(
                RepositoryBuildStatus, repository=repo_string, build_uuid=build_request.uuid
            ),
        }
        return resp, 201, headers


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/builds")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
class TriggerBuildList(RepositoryParamResource):
    """
    Resource to represent builds that were activated from the specified trigger.
    """

    schemas = TRIGGER_RESPONSE_SCHEMAS

    @require_repo_admin(allow_for_global_readonly_superuser=True, allow_for_superuser=True)
    @disallow_for_app_repositories
    @parse_args()
    @query_param("limit", "The maximum number of builds to return", type=int, default=5)
    @nickname("listTriggerRecentBuilds")
    @define_json_response("BuildListResponse")
    def get(self, namespace_name, repo_name, trigger_uuid, parsed_args):
        """
        List the builds started by the specified trigger.
        """
        limit = parsed_args["limit"]
        builds = model.build.list_trigger_builds(namespace_name, repo_name, trigger_uuid, limit)
        return {"builds": [build_status_view(bld) for bld in builds]}


FIELD_VALUE_LIMIT = 30


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/fields/<field_name>")
@internal_only
class BuildTriggerFieldValues(RepositoryParamResource):
    """
    Custom verb to fetch a values list for a particular field name.

    Note: Response format varies based on field_name and handler type:
    - For GitHub/GitLab/Bitbucket handlers:
      - field_name="refs": returns array of objects with {"kind": "branch"|"tag", "name": string}
      - field_name="branch_name": returns array of branch name strings
      - field_name="tag_name": returns array of tag name strings
      - other field_name values: returns 404 Not Found
    - For Custom handler: always returns 404 Not Found (NotImplementedError)
    """

    schemas = TRIGGER_RESPONSE_SCHEMAS

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("listTriggerFieldValues")
    @define_json_response("FieldValuesResponse")
    def post(self, namespace_name, repo_name, trigger_uuid, field_name):
        """
        List the field values for a custom run field.
        """
        trigger = get_trigger(trigger_uuid)

        config = request.get_json() or None
        if AdministerRepositoryPermission(namespace_name, repo_name).can():
            handler = BuildTriggerHandler.get_handler(trigger, config)
            values = handler.list_field_values(field_name, limit=FIELD_VALUE_LIMIT)

            if values is None:
                raise NotFound()

            return {"values": values}
        else:
            raise Unauthorized()


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/sources")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
@internal_only
class BuildTriggerSources(RepositoryParamResource):
    """
    Custom verb to fetch the list of build sources for the trigger config.

    Note: Response format varies by handler type:
    - GitHub: has_admin_permissions is always true; last_updated is 0 if no push date
    - GitLab: last_updated may be omitted if invalid; has_admin_permissions based on access level
    - Bitbucket: has_admin_permissions based on read_only flag
    - Custom handler: always returns 404 Not Found (NotImplementedError)
    """

    schemas = {
        "BuildTriggerSourcesRequest": {
            "type": "object",
            "description": "Specifies the namespace under which to fetch sources",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "The namespace for which to fetch sources",
                },
            },
        },
        **TRIGGER_RESPONSE_SCHEMAS,
    }

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @disallow_for_non_normal_repositories
    @disallow_for_user_namespace
    @nickname("listTriggerBuildSources")
    @validate_json_request("BuildTriggerSourcesRequest")
    @define_json_response("SourcesResponse")
    def post(self, namespace_name, repo_name, trigger_uuid):
        """
        List the build sources for the trigger configuration thus far.
        """
        namespace = request.get_json().get("namespace")
        if namespace is None:
            raise InvalidRequest()

        trigger = get_trigger(trigger_uuid)

        user_permission = UserAdminPermission(trigger.connected_user.username)
        if user_permission.can():
            handler = BuildTriggerHandler.get_handler(trigger)

            try:
                return {"sources": handler.list_build_sources_for_namespace(namespace)}
            except TriggerException as rre:
                raise InvalidRequest(str(rre)) from rre
        else:
            raise Unauthorized()


@resource("/v1/repository/<apirepopath:repository>/trigger/<trigger_uuid>/namespaces")
@path_param("repository", "The full path of the repository. e.g. namespace/name")
@path_param("trigger_uuid", "The UUID of the build trigger")
@internal_only
class BuildTriggerSourceNamespaces(RepositoryParamResource):
    """
    Custom verb to fetch the list of namespaces (orgs, projects, etc) for the trigger config.

    Note: Response format varies by handler type:
    - GitHub: url is empty for organizations; score is private repo count for personal namespace, 0 for orgs
    - GitLab: id is numeric string; avatar_url may be null; score increments with namespace occurrences
    - Bitbucket: url is always https://bitbucket.org/{owner}; score is repository count
    - Custom handler: always returns 404 Not Found (NotImplementedError)
    """

    schemas = TRIGGER_RESPONSE_SCHEMAS

    @require_repo_admin(allow_for_superuser=True)
    @disallow_for_app_repositories
    @nickname("listTriggerBuildSourceNamespaces")
    @define_json_response("NamespacesResponse")
    def get(self, namespace_name, repo_name, trigger_uuid):
        """
        List the build sources for the trigger configuration thus far.
        """
        trigger = get_trigger(trigger_uuid)

        user_permission = UserAdminPermission(trigger.connected_user.username)
        if user_permission.can():
            handler = BuildTriggerHandler.get_handler(trigger)

            try:
                return {"namespaces": handler.list_build_source_namespaces()}
            except TriggerException as rre:
                raise InvalidRequest(str(rre)) from rre
        else:
            raise Unauthorized()
