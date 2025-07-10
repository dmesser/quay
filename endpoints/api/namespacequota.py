import logging
from typing import Any, Dict

import bitmath
from flask import request

import features
from auth import scopes
from auth.auth_context import get_authenticated_user
from auth.permissions import OrganizationMemberPermission, SuperUserPermission
from data import model
from data.model import config
from endpoints.api import (
    ApiResource,
    allow_if_global_readonly_superuser,
    allow_if_superuser,
    define_json_response,
    nickname,
    request_error,
    require_scope,
    require_user_admin,
    resource,
    show_if,
    validate_json_request,
)
from endpoints.exception import NotFound, Unauthorized

logger = logging.getLogger(__name__)


def quota_view(quota, default_config=False):
    quota_limits = []

    if quota:
        quota_limits = list(model.namespacequota.get_namespace_quota_limit_list(quota))
    else:
        # If no quota is defined for the org, return systems default quota if set
        if config.app_config.get("DEFAULT_SYSTEM_REJECT_QUOTA_BYTES") != 0:
            quota = model.namespacequota.get_system_default_quota()
            default_config = True

    return {
        "id": quota.id,
        "limit_bytes": quota.limit_bytes,
        "limit": bitmath.Byte(quota.limit_bytes).best_prefix().format("{value:.1f} {unit}"),
        "default_config": default_config,
        "limits": [limit_view(limit) for limit in quota_limits],
        "default_config_exists": (
            True if config.app_config.get("DEFAULT_SYSTEM_REJECT_QUOTA_BYTES") != 0 else False
        ),
    }


def limit_view(limit):
    return {
        "id": limit.id,
        "type": limit.quota_type.name,
        "limit_percent": limit.percent_of_limit,
    }


def get_quota(namespace_name, quota_id):
    quota = model.namespacequota.get_namespace_quota(namespace_name, quota_id)
    if quota is None:
        raise NotFound()
    return quota


@resource("/v1/organization/<orgname>/quota")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class OrganizationQuotaList(ApiResource):
    schemas: Dict[str, Any] = {
        "NewOrgQuotaInBytes": {
            "type": "object",
            "description": "Organization quota with byte limit",
            "required": ["limit_bytes"],
            "properties": {
                "limit_bytes": {
                    "type": "integer",
                    "description": "Number of bytes the organization is allowed",
                },
            },
        },
        "NewOrgQuotaHumanReadable": {
            "type": "object",
            "description": "Organization quota with human readable limit",
            "required": ["limit"],
            "properties": {
                "limit": {
                    "type": "string",
                    "description": "Human readable storage capacity of the organization",
                    "pattern": r"^(\d+\s?(B|KiB|MiB|GiB|TiB|EiB|ZiB|YiB|Ki|Mi|Gi|Ti|Pi|Ei|Zi|Yi|KB|MB|GB|TB|PB|EB|ZB|YB|K|M|G|T|P|E|Z|Y)?)$",
                },
            },
        },
        "NewOrgQuota": {
            "type": "object",
            "description": "Description of a new organization quota",
            "oneOf": [
                {"$ref": "#/definitions/NewOrgQuotaInBytes"},
                {"$ref": "#/definitions/NewOrgQuotaHumanReadable"},
            ],
        },
        "QuotaLimit": {
            "type": "object",
            "description": "A quota limit configuration",
            "properties": {
                "id": {
                    "type": "integer",
                    "description": "Unique identifier for the quota limit",
                },
                "type": {
                    "type": "string",
                    "description": "Type of quota limit (e.g., 'Warning', 'Reject')",
                    "enum": ["Warning", "Reject"],
                },
                "limit_percent": {
                    "type": "integer",
                    "description": "Percentage of the quota limit at which this limit applies",
                    "minimum": 0,
                    "maximum": 100,
                },
            },
            "required": ["id", "type", "limit_percent"],
        },
        "QuotaView": {
            "type": "object",
            "description": "Complete quota information including limits",
            "properties": {
                "id": {
                    "type": ["integer", "null"],
                    "x-nullable": True,
                    "description": "Unique identifier for the quota",
                },
                "limit_bytes": {
                    "type": "integer",
                    "description": "Quota limit in bytes",
                },
                "limit": {
                    "type": "string",
                    "description": "Human readable quota limit (e.g., '1.0 GiB')",
                },
                "default_config": {
                    "type": "boolean",
                    "description": "Whether this is using the default system configuration",
                },
                "limits": {
                    "type": "array",
                    "description": "List of quota limit configurations",
                    "items": {"$ref": "#/definitions/QuotaLimit"},
                },
                "default_config_exists": {
                    "type": "boolean",
                    "description": "Whether a default system quota configuration exists",
                },
            },
            "required": [
                "id",
                "limit_bytes",
                "limit",
                "default_config",
                "limits",
                "default_config_exists",
            ],
        },
        "QuotaList": {
            "type": "array",
            "description": "List of organization quotas",
            "items": {"$ref": "#/definitions/QuotaView"},
        },
        "CreateResponse": {
            "type": "string",
            "description": "Success message for quota creation",
            "enum": ["Created"],
        },
    }

    @nickname("listOrganizationQuota")
    @define_json_response("QuotaList")
    def get(self, orgname):
        orgperm = OrganizationMemberPermission(orgname)
        if (
            not orgperm.can()
            and not SuperUserPermission().can()
            and not allow_if_global_readonly_superuser()
        ):
            raise Unauthorized()

        try:
            org = model.organization.get_organization(orgname)
        except model.InvalidOrganizationException:
            raise NotFound()

        default_config = False
        quotas = model.namespacequota.get_namespace_quota_list(orgname)

        # If no quota is defined for the org, return systems default quota
        if not quotas and config.app_config.get("DEFAULT_SYSTEM_REJECT_QUOTA_BYTES") != 0:
            quotas = [model.namespacequota.get_system_default_quota(orgname)]
            default_config = True

        return [quota_view(quota, default_config) for quota in quotas]

    @nickname("createOrganizationQuota")
    @validate_json_request("NewOrgQuota")
    @define_json_response("CreateResponse")
    @require_scope(scopes.SUPERUSER)
    def post(self, orgname):
        """
        Create a new organization quota.
        """
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota_data = request.get_json()

        if "limit" in quota_data:
            try:
                limit_bytes = bitmath.parse_string_unsafe(quota_data["limit"]).to_Byte().value
            except ValueError:
                raise request_error(
                    message="Invalid limit format, use a number followed by a unit (e.g. 1GiB)"
                )
        else:
            limit_bytes = quota_data["limit_bytes"]

        try:
            org = model.organization.get_organization(orgname)
        except model.InvalidOrganizationException:
            raise NotFound()

        # Currently only supporting one quota definition per namespace
        quotas = model.namespacequota.get_namespace_quota_list(orgname)
        if quotas:
            raise request_error(message="Organization quota for '%s' already exists" % orgname)

        try:
            model.namespacequota.create_namespace_quota(org, limit_bytes)
            return "Created", 201
        except model.DataModelException as ex:
            raise request_error(exception=ex)


@resource("/v1/organization/<orgname>/quota/<quota_id>")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class OrganizationQuota(ApiResource):
    schemas = {
        **OrganizationQuotaList.schemas,
        "UpdateOrgQuotaInBytes": {
            "type": "object",
            "description": "Update organization quota with byte limit",
            "required": ["limit_bytes"],
            "properties": {
                "limit_bytes": {
                    "type": "integer",
                    "description": "Number of bytes the organization is allowed",
                },
            },
            "additionalProperties": False,
        },
        "UpdateOrgQuotaHumanReadable": {
            "type": "object",
            "description": "Update organization quota with human readable limit",
            "required": ["limit"],
            "properties": {
                "limit": {
                    "type": "string",
                    "description": "Human readable storage capacity of the organization",
                    "pattern": r"^(\d+\s?(B|KiB|MiB|GiB|TiB|PiB|EiB|ZiB|YiB|Ki|Mi|Gi|Ti|Pi|Ei|Zi|Yi|KB|MB|GB|TB|PB|EB|ZB|YB|K|M|G|T|P|E|Z|Y)?)$",
                },
            },
            "additionalProperties": False,
        },
        "UpdateOrgQuota": {
            "type": "object",
            "description": "Description of updating an organization quota",
            "oneOf": [
                {"$ref": "#/definitions/UpdateOrgQuotaInBytes"},
                {"$ref": "#/definitions/UpdateOrgQuotaHumanReadable"},
                {
                    "type": "object",
                    "description": "Empty update - no changes to quota size",
                    "properties": {},
                    "additionalProperties": False,
                },
            ],
        },
    }

    @nickname("getOrganizationQuota")
    @define_json_response("QuotaView")
    def get(self, orgname, quota_id):
        orgperm = OrganizationMemberPermission(orgname)
        if (
            not orgperm.can()
            and not SuperUserPermission().can()
            and not allow_if_global_readonly_superuser()
        ):
            raise Unauthorized()

        quota = get_quota(orgname, quota_id)

        return quota_view(quota)

    @nickname("changeOrganizationQuota")
    @require_scope(scopes.SUPERUSER)
    @validate_json_request("UpdateOrgQuota")
    @define_json_response("QuotaView")
    def put(self, orgname, quota_id):
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota_data = request.get_json()
        quota = get_quota(orgname, quota_id)

        try:
            limit_bytes = None

            if "limit" in quota_data:
                try:
                    limit_bytes = bitmath.parse_string_unsafe(quota_data["limit"]).to_Byte().value
                except ValueError:
                    raise request_error(
                        message="Invalid limit format, use a number followed by a unit (e.g. 1GiB)"
                    )
            elif "limit_bytes" in quota_data:
                limit_bytes = quota_data["limit_bytes"]

            if limit_bytes:
                model.namespacequota.update_namespace_quota_size(quota, limit_bytes)
        except model.DataModelException as ex:
            raise request_error(exception=ex)

        return quota_view(quota)

    @nickname("deleteOrganizationQuota")
    @require_scope(scopes.SUPERUSER)
    def delete(self, orgname, quota_id):
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota = get_quota(orgname, quota_id)

        # Exceptions by`delete_instance` are unexpected and raised
        model.namespacequota.delete_namespace_quota(quota)

        return "", 204


@resource("/v1/organization/<orgname>/quota/<quota_id>/limit")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class OrganizationQuotaLimitList(ApiResource):
    schemas = {
        **OrganizationQuotaList.schemas,
        "NewOrgQuotaLimit": {
            "type": "object",
            "description": "Description of a new organization quota limit",
            "required": ["type", "threshold_percent"],
            "properties": {
                "type": {
                    "type": "string",
                    "description": 'Type of quota limit: "Warning" or "Reject"',
                },
                "threshold_percent": {
                    "type": "integer",
                    "description": "Quota threshold, in percent of quota",
                },
            },
        },
        "QuotaLimitList": {
            "type": "array",
            "description": "List of quota limits",
            "items": {"$ref": "#/definitions/QuotaLimit"},
        },
    }

    @nickname("listOrganizationQuotaLimit")
    @define_json_response("QuotaLimitList")
    def get(self, orgname, quota_id):
        orgperm = OrganizationMemberPermission(orgname)
        if (
            not orgperm.can()
            and not allow_if_superuser()
            and not allow_if_global_readonly_superuser()
        ):
            raise Unauthorized()

        quota = get_quota(orgname, quota_id)
        return [
            limit_view(limit)
            for limit in model.namespacequota.get_namespace_quota_limit_list(quota)
        ]

    @nickname("createOrganizationQuotaLimit")
    @validate_json_request("NewOrgQuotaLimit")
    @define_json_response("CreateResponse")
    @require_scope(scopes.SUPERUSER)
    def post(self, orgname, quota_id):
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota_limit_data = request.get_json()
        quota_type = quota_limit_data["type"]
        quota_limit_threshold = quota_limit_data["threshold_percent"]

        quota = get_quota(orgname, quota_id)

        quota_limit = model.namespacequota.get_namespace_quota_limit_list(
            quota,
            quota_type=quota_type,
            percent_of_limit=quota_limit_threshold,
        )

        if quota_limit:
            msg = "Quota limit already exists"
            raise request_error(message=msg)

        if quota_limit_data["type"].lower() == "reject" and quota_limit:
            raise request_error(message="Only one quota limit of type 'Reject' allowed.")

        try:
            model.namespacequota.create_namespace_quota_limit(
                quota,
                quota_type,
                quota_limit_threshold,
            )
            return "Created", 201
        except model.DataModelException as ex:
            raise request_error(exception=ex)


@resource("/v1/organization/<orgname>/quota/<quota_id>/limit/<limit_id>")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class OrganizationQuotaLimit(ApiResource):
    schemas = {
        **OrganizationQuotaLimitList.schemas,
        "UpdateOrgQuotaLimit": {
            "type": "object",
            "description": "Description of changing organization quota limit",
            "properties": {
                "type": {
                    "type": "string",
                    "description": 'Type of quota limit: "Warning" or "Reject"',
                },
                "threshold_percent": {
                    "type": "integer",
                    "description": "Quota threshold, in percent of quota",
                },
            },
        },
    }

    @nickname("getOrganizationQuotaLimit")
    @define_json_response("QuotaLimit")
    def get(self, orgname, quota_id, limit_id):
        orgperm = OrganizationMemberPermission(orgname)
        if (
            not orgperm.can()
            and not allow_if_superuser()
            and not allow_if_global_readonly_superuser()
        ):
            raise Unauthorized()

        quota = get_quota(orgname, quota_id)
        quota_limit = model.namespacequota.get_namespace_quota_limit(quota, limit_id)
        if quota_limit is None:
            raise NotFound()

        return limit_view(quota_limit)

    @nickname("changeOrganizationQuotaLimit")
    @validate_json_request("UpdateOrgQuotaLimit")
    @define_json_response("QuotaView")
    @require_scope(scopes.SUPERUSER)
    def put(self, orgname, quota_id, limit_id):
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota_limit_data = request.get_json()

        quota = get_quota(orgname, quota_id)
        quota_limit = model.namespacequota.get_namespace_quota_limit(quota, limit_id)
        if quota_limit is None:
            raise NotFound()

        if "type" in quota_limit_data:
            new_type = quota_limit_data["type"]
            model.namespacequota.update_namespace_quota_limit_type(quota_limit, new_type)
        if "threshold_percent" in quota_limit_data:
            new_threshold = quota_limit_data["threshold_percent"]
            model.namespacequota.update_namespace_quota_limit_threshold(quota_limit, new_threshold)

        return quota_view(quota)

    @nickname("deleteOrganizationQuotaLimit")
    @require_scope(scopes.SUPERUSER)
    def delete(self, orgname, quota_id, limit_id):
        if not SuperUserPermission().can():
            raise Unauthorized()

        quota = get_quota(orgname, quota_id)
        quota_limit = model.namespacequota.get_namespace_quota_limit(quota, limit_id)
        if quota_limit is None:
            raise NotFound()

        try:
            # Exceptions by`delete_instance` are unexpected and raised
            model.namespacequota.delete_namespace_quota_limit(quota_limit)
            return "", 204
        except model.DataModelException as ex:
            raise request_error(exception=ex)


@resource("/v1/user/quota")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class UserQuotaList(ApiResource):

    schemas = OrganizationQuotaList.schemas

    @require_user_admin()
    @nickname("listUserQuota")
    @define_json_response("QuotaList")
    def get(self):
        parent = get_authenticated_user()
        user_quotas = model.namespacequota.get_namespace_quota_list(parent.username)

        return [quota_view(quota) for quota in user_quotas]


@resource("/v1/user/quota/<quota_id>")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class UserQuota(ApiResource):
    schemas = OrganizationQuotaList.schemas

    @require_user_admin()
    @nickname("getUserQuota")
    @define_json_response("QuotaView")
    def get(self, quota_id):
        parent = get_authenticated_user()
        quota = get_quota(parent.username, quota_id)

        return quota_view(quota)


@resource("/v1/user/quota/<quota_id>/limit")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class UserQuotaLimitList(ApiResource):

    schemas = OrganizationQuotaLimitList.schemas

    @require_user_admin()
    @nickname("listUserQuotaLimit")
    @define_json_response("QuotaLimitList")
    def get(self, quota_id):
        parent = get_authenticated_user()
        quota = get_quota(parent.username, quota_id)

        return [
            limit_view(limit)
            for limit in model.namespacequota.get_namespace_quota_limit_list(quota)
        ]


@resource("/v1/user/quota/<quota_id>/limit/<limit_id>")
@show_if(features.SUPER_USERS)
@show_if(features.QUOTA_MANAGEMENT and features.EDIT_QUOTA)
class UserQuotaLimit(ApiResource):
    schemas = OrganizationQuotaList.schemas

    @require_user_admin()
    @nickname("getUserQuotaLimit")
    @define_json_response("QuotaLimit")
    def get(self, quota_id, limit_id):
        parent = get_authenticated_user()
        quota = get_quota(parent.username, quota_id)
        quota_limit = model.namespacequota.get_namespace_quota_limit(quota, limit_id)
        if quota_limit is None:
            raise NotFound()

        return limit_view(quota_limit)
