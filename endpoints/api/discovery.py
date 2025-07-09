# TODO to extract the discovery stuff into a util at the top level and then use it both here and config_app discovery.py
"""
API discovery information.
"""

import logging
import re
import sys
from collections import OrderedDict

from flask_restful import reqparse

from app import app
from auth import scopes
from endpoints.api import (
    ApiResource,
    method_metadata,
    nickname,
    parse_args,
    query_param,
    resource,
)
from endpoints.decorators import anon_allowed
from util.parsing import truthy_bool

logger = logging.getLogger(__name__)


PARAM_REGEX = re.compile(r"<([^:>]+:)*([\w]+)>")


TYPE_CONVERTER = {
    truthy_bool: "boolean",
    str: "string",
    reqparse.text_type: "string",
    int: "integer",
}

PREFERRED_URL_SCHEME = app.config["PREFERRED_URL_SCHEME"]
SERVER_HOSTNAME = app.config["SERVER_HOSTNAME"]
if SERVER_HOSTNAME == "quay.io" or SERVER_HOSTNAME == "stage.quay.io":
    TERMS_OF_SERVICE_URL = "https://www.openshift.com/legal/terms"
else:
    if app.config["FOOTER_LINKS"]:
        TERMS_OF_SERVICE_URL = (
            app.config["FOOTER_LINKS"]["TERMS_OF_SERVICE_URL"]
            if app.config["FOOTER_LINKS"]["TERMS_OF_SERVICE_URL"]
            else ""
        )
    else:
        TERMS_OF_SERVICE_URL = ""
CONTACT_EMAIL = app.config["MAIL_DEFAULT_SENDER"]


def fully_qualified_name(method_view_class):
    return "%s.%s" % (method_view_class.__module__, method_view_class.__name__)


def swagger_route_data(include_internal=False, compact=False):
    def swagger_parameter(
        name, description, kind="path", param_type="string", required=True, enum=None, schema=None
    ):
        # https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#parameterObject
        parameter_info = {"name": name, "in": kind, "required": required}

        if not compact:
            parameter_info["description"] = description or ""

        if schema:
            parameter_info["schema"] = {"$ref": "#/definitions/%s" % schema}
        else:
            parameter_info["type"] = param_type

        if enum is not None and len(list(enum)) > 0:
            parameter_info["enum"] = list(enum)

        return parameter_info

    def extract_refs_from_schema(schema_obj):
        """Extract all $ref values from a schema object recursively."""
        refs = set()

        if isinstance(schema_obj, dict):
            for key, value in schema_obj.items():
                if key == "$ref" and isinstance(value, str) and value.startswith("#/definitions/"):
                    ref_name = value.replace("#/definitions/", "")
                    refs.add(ref_name)
                else:
                    refs.update(extract_refs_from_schema(value))
        elif isinstance(schema_obj, list):
            for item in schema_obj:
                refs.update(extract_refs_from_schema(item))

        return refs

    def add_schema_and_refs(schema_name, view_class, models, processed_schemas):
        """Add a schema and all its referenced schemas to the models dict."""
        if schema_name in processed_schemas:
            return

        processed_schemas.add(schema_name)

        if hasattr(view_class, "schemas") and schema_name in view_class.schemas:
            schema = view_class.schemas[schema_name]
            models[schema_name] = schema

            # Find all referenced schemas
            refs = extract_refs_from_schema(schema)
            for ref in refs:
                add_schema_and_refs(ref, view_class, models, processed_schemas)

    paths = {}
    models = {}
    tags = []
    tags_added = set()
    operationIds = set()
    processed_schemas = set()

    for rule in app.url_map.iter_rules():
        endpoint_method = app.view_functions[rule.endpoint]

        # Verify that we have a view class for this API method.
        if not "view_class" in dir(endpoint_method):
            continue

        view_class = endpoint_method.view_class

        # Hide the class if it is internal.
        internal = method_metadata(view_class, "internal")
        if not include_internal and internal:
            continue

        # Build the tag.
        parts = fully_qualified_name(view_class).split(".")
        tag_name = parts[-2]
        if not tag_name in tags_added:
            tags_added.add(tag_name)
            tags.append(
                {
                    "name": tag_name,
                    "description": (sys.modules[view_class.__module__].__doc__ or "").strip(),
                }
            )

        # Build the Swagger data for the path.
        swagger_path = PARAM_REGEX.sub(r"{\2}", rule.rule)
        full_name = fully_qualified_name(view_class)
        path_swagger = {"x-name": full_name, "x-path": swagger_path, "x-tag": tag_name}

        if include_internal:
            related_user_res = method_metadata(view_class, "related_user_resource")
            if related_user_res is not None:
                path_swagger["x-user-related"] = fully_qualified_name(related_user_res)

        paths[swagger_path] = path_swagger

        # Add any global path parameters.
        param_data_map = (
            view_class.__api_path_params if "__api_path_params" in dir(view_class) else {}
        )
        if param_data_map:
            path_parameters_swagger = []
            for path_parameter in param_data_map:
                description = param_data_map[path_parameter].get("description")
                path_parameters_swagger.append(swagger_parameter(path_parameter, description))

            path_swagger["parameters"] = path_parameters_swagger

        # Add the individual HTTP operations.
        method_names = list(rule.methods.difference(["HEAD", "OPTIONS"]))
        for method_name in method_names:
            # https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#operation-object
            method = getattr(view_class, method_name.lower(), None)
            if method is None:
                logger.debug("Unable to find method for %s in class %s", method_name, view_class)
                continue

            _operationId = method_metadata(method, "nickname")

            if isinstance(_operationId, list):
                operationId = None
                for oid in _operationId:
                    if oid in operationIds:
                        continue
                    else:
                        operationId = oid

                        break

                if operationId is None:
                    raise Exception("Duplicate operation Id: %s" % operationId)

            else:
                operationId = _operationId

            operation_swagger = {
                "operationId": operationId,
                "parameters": [],
            }

            if operationId is None:
                continue

            if operationId in operationIds:
                raise Exception("Duplicate operation Id: %s" % operationId)

            operationIds.add(operationId)

            if not compact:
                operation_swagger.update(
                    {
                        "description": method.__doc__.strip() if method.__doc__ else "",
                        "tags": [tag_name],
                    }
                )

            # Mark the method as internal.
            internal = method_metadata(method, "internal")
            if internal is not None:
                operation_swagger["x-internal"] = True

            if include_internal:
                requires_fresh_login = method_metadata(method, "requires_fresh_login")
                if requires_fresh_login is not None:
                    operation_swagger["x-requires-fresh-login"] = True

            # Add the path parameters.
            if rule.arguments:
                for path_parameter in rule.arguments:
                    description = param_data_map.get(path_parameter, {}).get("description")
                    operation_swagger["parameters"].append(
                        swagger_parameter(path_parameter, description)
                    )

            # Add the query parameters.
            if "__api_query_params" in dir(method):
                for query_parameter_info in method.__api_query_params:
                    name = query_parameter_info["name"]
                    description = query_parameter_info["help"]
                    param_type = TYPE_CONVERTER[query_parameter_info["type"]]
                    required = query_parameter_info["required"]

                    operation_swagger["parameters"].append(
                        swagger_parameter(
                            name,
                            description,
                            kind="query",
                            param_type=param_type,
                            required=required,
                            enum=query_parameter_info["choices"],
                        )
                    )

            # Add the OAuth security block.
            # https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#securityRequirementObject
            scope = method_metadata(method, "oauth2_scope")
            if scope and not compact:
                operation_swagger["security"] = [{"oauth2_implicit": [scope.scope], "bearer": []}]

            # Add the responses block.
            # https://github.com/swagger-api/swagger-spec/blob/master/versions/2.0.md#responsesObject
            response_schema_name = method_metadata(method, "response_schema")
            if not compact:
                if response_schema_name:
                    add_schema_and_refs(response_schema_name, view_class, models, processed_schemas)

                models["ApiError"] = {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "integer",
                            "description": "Status code of the response.",
                        },
                        "type": {
                            "type": "string",
                            "description": "Reference to the type of the error.",
                        },
                        "detail": {
                            "type": "string",
                            "description": "Details about the specific instance of the error.",
                        },
                        "title": {
                            "type": "string",
                            "description": "Unique error code to identify the type of error.",
                        },
                        "error_message": {
                            "type": "string",
                            "description": "Deprecated; alias for detail",
                        },
                        "error_type": {
                            "type": "string",
                            "description": "Deprecated; alias for detail",
                        },
                    },
                    "required": [
                        "status",
                        "type",
                        "title",
                    ],
                }

                responses = {
                    "400": {
                        "description": "Bad Request",
                    },
                    "401": {
                        "description": "Session required",
                    },
                    "403": {
                        "description": "Unauthorized access",
                    },
                    "404": {
                        "description": "Not found",
                    },
                }

                for _, body in list(responses.items()):
                    body["schema"] = {"$ref": "#/definitions/ApiError"}

                if method_name == "DELETE":
                    responses["204"] = {"description": "Deleted"}
                elif method_name == "POST":
                    responses["201"] = {"description": "Successful creation"}
                else:
                    responses["200"] = {"description": "Successful invocation"}

                    if response_schema_name:
                        responses["200"]["schema"] = {
                            "$ref": "#/definitions/%s" % response_schema_name
                        }

                operation_swagger["responses"] = responses

            # Add the request block.
            request_schema_name = method_metadata(method, "request_schema")
            if request_schema_name and not compact:
                add_schema_and_refs(request_schema_name, view_class, models, processed_schemas)

                operation_swagger["parameters"].append(
                    swagger_parameter(
                        "body", "Request body contents.", kind="body", schema=request_schema_name
                    )
                )

            # Add the operation to the parent path.
            if not internal or (internal and include_internal):
                path_swagger[method_name.lower()] = operation_swagger

    tags.sort(key=lambda t: t["name"])
    paths = OrderedDict(sorted(list(paths.items()), key=lambda p: p[1]["x-tag"]))

    if compact:
        return {"paths": paths}

    swagger_data = {
        "swagger": "2.0",
        "host": SERVER_HOSTNAME,
        "basePath": "/",
        "schemes": [PREFERRED_URL_SCHEME],
        "info": {
            "version": "v1",
            "title": "Quay Frontend",
            "description": (
                "This API allows you to perform many of the operations required to work "
                "with Quay repositories, users, and organizations."
            ),
            "termsOfService": TERMS_OF_SERVICE_URL,
            "contact": {"email": CONTACT_EMAIL},
        },
        "securityDefinitions": {
            "oauth2_implicit": {
                "type": "oauth2",
                "flow": "implicit",
                "authorizationUrl": "%s://%s/oauth/authorize"
                % (PREFERRED_URL_SCHEME, SERVER_HOSTNAME),
                "scopes": {
                    scope.scope: scope.description
                    for scope in list(scopes.app_scopes(app.config).values())
                },
            },
            "bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
            },
        },
        "paths": paths,
        "definitions": models,
        "tags": tags,
    }

    return swagger_data


def openapi_route_data(include_internal=False, compact=False):
    """Generate OpenAPI 3.0 specification from the API routes."""

    def openapi_parameter(
        name,
        description,
        location="path",
        param_type="string",
        required=True,
        enum=None,
        schema=None,
    ):
        # OpenAPI 3.0 parameter structure
        parameter_info = {
            "name": name,
            "in": location,
            "required": required,
        }

        if not compact:
            parameter_info["description"] = description or ""

        if schema:
            parameter_info["schema"] = {"$ref": "#/components/schemas/%s" % schema}
        else:
            parameter_info["schema"] = {"type": param_type}
            if enum is not None and len(list(enum)) > 0:
                parameter_info["schema"]["enum"] = list(enum)

        return parameter_info

    def convert_swagger_to_openapi3(schema_obj):
        """Convert Swagger 2.0 schema features to OpenAPI 3.0 format."""
        if isinstance(schema_obj, dict):
            new_dict = {}
            for key, value in schema_obj.items():
                if key == "type" and isinstance(value, list) and "null" in value:
                    # Convert type: ["string", "null"] to type: "string" with nullable: true
                    non_null_types = [t for t in value if t != "null"]
                    if len(non_null_types) == 1:
                        new_dict["type"] = non_null_types[0]
                        new_dict["nullable"] = True
                    else:
                        # If there are multiple non-null types, keep as is
                        new_dict[key] = value
                elif key == "oneOf" and isinstance(value, list):
                    # Handle oneOf with null type
                    non_null_items = [
                        item
                        for item in value
                        if not (isinstance(item, dict) and item.get("type") == "null")
                    ]
                    if (
                        len(value) == 2
                        and len(non_null_items) == 1
                        and any(
                            isinstance(item, dict) and item.get("type") == "null" for item in value
                        )
                    ):
                        # Convert oneOf: [{...}, {type: "null"}] to the non-null schema with nullable: true
                        result = convert_swagger_to_openapi3(non_null_items[0])
                        result["nullable"] = True
                        return result
                    else:
                        new_dict[key] = [convert_swagger_to_openapi3(item) for item in value]
                elif key == "discriminator" and isinstance(value, str):
                    # Convert discriminator from string to object format
                    new_dict[key] = {"propertyName": value}
                elif key == "x-nullable":
                    # Skip x-nullable as we're using the standard nullable property
                    continue
                else:
                    new_dict[key] = convert_swagger_to_openapi3(value)
            return new_dict
        elif isinstance(schema_obj, list):
            return [convert_swagger_to_openapi3(item) for item in schema_obj]
        else:
            return schema_obj

    def extract_refs_from_schema(
        schema_obj, old_prefix="#/definitions/", new_prefix="#/components/schemas/"
    ):
        """Extract and convert all $ref values from a schema object recursively."""
        if isinstance(schema_obj, dict):
            new_dict = {}
            for key, value in schema_obj.items():
                if key == "$ref" and isinstance(value, str) and value.startswith(old_prefix):
                    ref_name = value.replace(old_prefix, "")
                    new_dict[key] = new_prefix + ref_name
                else:
                    new_dict[key] = extract_refs_from_schema(value, old_prefix, new_prefix)
            return new_dict
        elif isinstance(schema_obj, list):
            return [extract_refs_from_schema(item, old_prefix, new_prefix) for item in schema_obj]
        else:
            return schema_obj

    def add_schema_and_refs(schema_name, view_class, schemas, processed_schemas):
        """Add a schema and all its referenced schemas to the schemas dict."""
        if schema_name in processed_schemas:
            return

        processed_schemas.add(schema_name)

        if hasattr(view_class, "schemas") and schema_name in view_class.schemas:
            schema = view_class.schemas[schema_name]
            # Convert all #/definitions/ refs to #/components/schemas/
            converted_schema = extract_refs_from_schema(schema)
            # Convert Swagger 2.0 features to OpenAPI 3.0 format
            converted_schema = convert_swagger_to_openapi3(converted_schema)
            schemas[schema_name] = converted_schema

            # Find all referenced schemas
            refs = set()

            def find_refs(obj):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if (
                            key == "$ref"
                            and isinstance(value, str)
                            and value.startswith("#/components/schemas/")
                        ):
                            ref_name = value.replace("#/components/schemas/", "")
                            refs.add(ref_name)
                        else:
                            find_refs(value)
                elif isinstance(obj, list):
                    for item in obj:
                        find_refs(item)

            find_refs(converted_schema)
            for ref in refs:
                add_schema_and_refs(ref, view_class, schemas, processed_schemas)

    paths = {}
    schemas = {}
    tags = []
    tags_added = set()
    operationIds = set()
    processed_schemas = set()

    # First pass - collect all route data similar to swagger_route_data
    for rule in app.url_map.iter_rules():
        endpoint_method = app.view_functions[rule.endpoint]

        # Verify that we have a view class for this API method.
        if not "view_class" in dir(endpoint_method):
            continue

        view_class = endpoint_method.view_class

        # Hide the class if it is internal.
        internal = method_metadata(view_class, "internal")
        if not include_internal and internal:
            continue

        # Build the tag.
        parts = fully_qualified_name(view_class).split(".")
        tag_name = parts[-2]
        if not tag_name in tags_added:
            tags_added.add(tag_name)
            tags.append(
                {
                    "name": tag_name,
                    "description": (sys.modules[view_class.__module__].__doc__ or "").strip(),
                }
            )

        # Build the OpenAPI data for the path.
        openapi_path = PARAM_REGEX.sub(r"{\2}", rule.rule)
        full_name = fully_qualified_name(view_class)
        path_item = {}

        if include_internal:
            related_user_res = method_metadata(view_class, "related_user_resource")
            if related_user_res is not None:
                path_item["x-user-related"] = fully_qualified_name(related_user_res)

        paths[openapi_path] = path_item

        # Add any global path parameters.
        param_data_map = (
            view_class.__api_path_params if "__api_path_params" in dir(view_class) else {}
        )
        path_parameters = []
        if param_data_map:
            for path_parameter in param_data_map:
                description = param_data_map[path_parameter].get("description")
                path_parameters.append(openapi_parameter(path_parameter, description))

        # Add the individual HTTP operations.
        method_names = list(rule.methods.difference(["HEAD", "OPTIONS"]))
        for method_name in method_names:
            method = getattr(view_class, method_name.lower(), None)
            if method is None:
                logger.debug("Unable to find method for %s in class %s", method_name, view_class)
                continue

            _operationId = method_metadata(method, "nickname")

            if isinstance(_operationId, list):
                operationId = None
                for oid in _operationId:
                    if oid in operationIds:
                        continue
                    else:
                        operationId = oid
                        break

                if operationId is None:
                    raise Exception("Duplicate operation Id: %s" % operationId)
            else:
                operationId = _operationId

            operation = {
                "operationId": operationId,
                "parameters": path_parameters[:],  # Copy path parameters
            }

            if operationId is None:
                continue

            if operationId in operationIds:
                raise Exception("Duplicate operation Id: %s" % operationId)

            operationIds.add(operationId)

            if not compact:
                operation.update(
                    {
                        "summary": method.__doc__.strip().split("\n")[0] if method.__doc__ else "",
                        "description": method.__doc__.strip() if method.__doc__ else "",
                        "tags": [tag_name],
                    }
                )

            # Mark the method as internal.
            internal = method_metadata(method, "internal")
            if internal is not None:
                operation["x-internal"] = True

            if include_internal:
                requires_fresh_login = method_metadata(method, "requires_fresh_login")
                if requires_fresh_login is not None:
                    operation["x-requires-fresh-login"] = True

            # Add the path parameters.
            if rule.arguments:
                for path_parameter in rule.arguments:
                    description = param_data_map.get(path_parameter, {}).get("description")
                    # Check if parameter already exists
                    if not any(p["name"] == path_parameter for p in operation["parameters"]):
                        operation["parameters"].append(
                            openapi_parameter(path_parameter, description)
                        )

            # Add the query parameters.
            if "__api_query_params" in dir(method):
                for query_parameter_info in method.__api_query_params:
                    name = query_parameter_info["name"]
                    description = query_parameter_info["help"]
                    param_type = TYPE_CONVERTER[query_parameter_info["type"]]
                    required = query_parameter_info["required"]

                    operation["parameters"].append(
                        openapi_parameter(
                            name,
                            description,
                            location="query",
                            param_type=param_type,
                            required=required,
                            enum=query_parameter_info["choices"],
                        )
                    )

            # Add the OAuth security block.
            scope = method_metadata(method, "oauth2_scope")
            if scope and not compact:
                operation["security"] = [{"oauth2_implicit": [scope.scope], "bearer": []}]

            # Add the responses block.
            response_schema_name = method_metadata(method, "response_schema")
            if not compact:
                if response_schema_name:
                    add_schema_and_refs(
                        response_schema_name, view_class, schemas, processed_schemas
                    )

                # Add ApiError schema
                schemas["ApiError"] = {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "integer",
                            "description": "Status code of the response.",
                        },
                        "type": {
                            "type": "string",
                            "description": "Reference to the type of the error.",
                        },
                        "detail": {
                            "type": "string",
                            "description": "Details about the specific instance of the error.",
                        },
                        "title": {
                            "type": "string",
                            "description": "Unique error code to identify the type of error.",
                        },
                        "error_message": {
                            "type": "string",
                            "description": "Deprecated; alias for detail",
                        },
                        "error_type": {
                            "type": "string",
                            "description": "Deprecated; alias for detail",
                        },
                    },
                    "required": [
                        "status",
                        "type",
                        "title",
                    ],
                }

                responses = {
                    "400": {
                        "description": "Bad Request",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiError"}
                            }
                        },
                    },
                    "401": {
                        "description": "Session required",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiError"}
                            }
                        },
                    },
                    "403": {
                        "description": "Unauthorized access",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiError"}
                            }
                        },
                    },
                    "404": {
                        "description": "Not found",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ApiError"}
                            }
                        },
                    },
                }

                if method_name == "DELETE":
                    responses["204"] = {"description": "Deleted"}
                elif method_name == "POST":
                    responses["201"] = {"description": "Successful creation"}
                    if response_schema_name:
                        responses["201"]["content"] = {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/%s" % response_schema_name}
                            }
                        }
                else:
                    responses["200"] = {"description": "Successful invocation"}
                    if response_schema_name:
                        responses["200"]["content"] = {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/%s" % response_schema_name}
                            }
                        }

                operation["responses"] = responses

            # Add the request body.
            request_schema_name = method_metadata(method, "request_schema")
            if request_schema_name and not compact:
                add_schema_and_refs(request_schema_name, view_class, schemas, processed_schemas)

                operation["requestBody"] = {
                    "description": "Request body contents.",
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/%s" % request_schema_name}
                        }
                    },
                }

            # Add the operation to the parent path.
            if not internal or (internal and include_internal):
                path_item[method_name.lower()] = operation

    tags.sort(key=lambda t: t["name"])
    paths = OrderedDict(sorted(list(paths.items()), key=lambda p: p[0]))

    if compact:
        return {"paths": paths}

    openapi_data = {
        "openapi": "3.0.0",
        "info": {
            "version": "v1",
            "title": "Quay Frontend",
            "description": (
                "This API allows you to perform many of the operations required to work "
                "with Quay repositories, users, and organizations."
            ),
            "termsOfService": TERMS_OF_SERVICE_URL,
            "contact": {"email": CONTACT_EMAIL},
        },
        "servers": [
            {
                "url": "{scheme}://{hostname}",
                "variables": {
                    "scheme": {
                        "default": PREFERRED_URL_SCHEME,
                        "enum": [PREFERRED_URL_SCHEME, "http", "https"],
                    },
                    "hostname": {
                        "default": SERVER_HOSTNAME,
                    },
                },
            }
        ],
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "oauth2_implicit": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": "%s://%s/oauth/authorize"
                            % (PREFERRED_URL_SCHEME, SERVER_HOSTNAME),
                            "scopes": {
                                scope.scope: scope.description
                                for scope in list(scopes.app_scopes(app.config).values())
                            },
                        }
                    },
                },
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
            },
        },
        "tags": tags,
    }

    return openapi_data


@resource("/v1/discovery")
class DiscoveryResource(ApiResource):
    """
    Ability to inspect the API for usage information and documentation.
    """

    @parse_args()
    @query_param("internal", "Whether to include internal APIs.", type=truthy_bool, default=False)
    @nickname("discovery")
    @anon_allowed
    def get(self, parsed_args):
        """
        List all of the API endpoints available in the swagger API format.
        """
        return swagger_route_data(parsed_args["internal"])


@resource("/v1/openapi")
class OpenAPIResource(ApiResource):
    """
    OpenAPI 3.0 specification for the Quay API.
    """

    @parse_args()
    @query_param("internal", "Whether to include internal APIs.", type=truthy_bool, default=False)
    @nickname("openapi")
    @anon_allowed
    def get(self, parsed_args):
        """
        List all of the API endpoints available in the OpenAPI 3.0 format.
        """
        return openapi_route_data(parsed_args["internal"])
