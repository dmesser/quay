# OpenAPI 3.0 Endpoint Documentation

## Overview

Quay now provides an OpenAPI 3.0 compliant specification endpoint alongside the existing Swagger 2.0 endpoint. This enables the use of modern tooling for generating client libraries and API documentation.

## Endpoints

### Swagger 2.0 (existing)
- **URL**: `/v1/discovery`
- **Method**: GET
- **Query Parameters**:
  - `internal` (boolean, optional): Whether to include internal APIs

### OpenAPI 3.0 (new)
- **URL**: `/v1/openapi`
- **Method**: GET
- **Query Parameters**:
  - `internal` (boolean, optional): Whether to include internal APIs

## Key Differences

The OpenAPI 3.0 endpoint provides the same API information as the Swagger 2.0 endpoint but with the following differences:

1. **Schema References**: All schema references use the OpenAPI 3.0 format (`#/components/schemas/`) instead of Swagger 2.0 format (`#/definitions/`)

2. **Security Definitions**: Security schemes are defined under `components.securitySchemes` instead of `securityDefinitions`

3. **Servers**: Uses the `servers` array with variables instead of separate `host`, `basePath`, and `schemes` fields

4. **Request Bodies**: Request bodies are defined using the `requestBody` field instead of a body parameter

5. **Response Content Types**: Responses include explicit content type definitions

6. **Nullable Types**: Nullable fields use the standard OpenAPI 3.0 `nullable: true` property instead of type arrays (e.g., `type: string, nullable: true` instead of `type: ["string", "null"]`)

7. **Discriminators**: Discriminator definitions use the OpenAPI 3.0 object format (e.g., `discriminator: { propertyName: "kind" }` instead of `discriminator: "kind"`)

## Usage Examples

### Fetch the OpenAPI specification
```bash
curl https://your-quay-instance.com/v1/openapi
```

### Fetch with internal APIs included
```bash
curl https://your-quay-instance.com/v1/openapi?internal=true
```

### Generate a client library using OpenAPI Generator
```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate a Python client
openapi-generator-cli generate \
  -i https://your-quay-instance.com/v1/openapi \
  -g python \
  -o ./quay-python-client
```

## Implementation Details

The OpenAPI endpoint reuses the same introspection logic as the Swagger endpoint, ensuring consistency between both specifications. The main differences are in the output format transformation to comply with OpenAPI 3.0 standards.

Both endpoints will always expose the same set of APIs, maintaining backward compatibility while enabling modern tooling support.
