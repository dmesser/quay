OCI_IMAGE_MANIFEST_CONTENT_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_INDEX_CONTENT_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_CONFIG_CONTENT_TYPE = "application/vnd.oci.image.config.v1+json"

OCI_IMAGE_TAR_LAYER_CONTENT_TYPE = "application/vnd.oci.image.layer.v1.tar"
OCI_IMAGE_TAR_GZIP_LAYER_CONTENT_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_IMAGE_TAR_ZSTD_LAYER_CONTENT_TYPE = "application/vnd.oci.image.layer.v1.tar+zstd"

OCI_IMAGE_DISTRIBUTABLE_LAYER_CONTENT_TYPES = [
    OCI_IMAGE_TAR_LAYER_CONTENT_TYPE,
    OCI_IMAGE_TAR_GZIP_LAYER_CONTENT_TYPE,
    OCI_IMAGE_TAR_ZSTD_LAYER_CONTENT_TYPE,
]

OCI_IMAGE_TAR_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPE = (
    "application/vnd.oci.image.layer.nondistributable.v1.tar"
)
OCI_IMAGE_TAR_GZIP_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPE = (
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
)

OCI_IMAGE_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPES = [
    OCI_IMAGE_TAR_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPE,
    OCI_IMAGE_TAR_GZIP_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPE,
]

OCI_IMAGE_LAYER_CONTENT_TYPES = (
    OCI_IMAGE_DISTRIBUTABLE_LAYER_CONTENT_TYPES + OCI_IMAGE_NON_DISTRIBUTABLE_LAYER_CONTENT_TYPES
)

OCI_CONTENT_TYPES = {OCI_IMAGE_MANIFEST_CONTENT_TYPE, OCI_IMAGE_INDEX_CONTENT_TYPE}

OCI_IMAGE_CREATED_ANNOTATION = "org.opencontainers.image.created"
OCI_LABEL_SCHEMA_BUILD_DATE = "org.label-schema.build-date"


def parse_annotation_created_datetime(annotations):
    """
    Extracts the creation datetime from OCI annotations, checking
    org.opencontainers.image.created first with org.label-schema.build-date as fallback.
    Returns a datetime or None.
    """
    from dateutil.parser import parse as parse_date

    for key in (OCI_IMAGE_CREATED_ANNOTATION, OCI_LABEL_SCHEMA_BUILD_DATE):
        value = annotations.get(key)
        if value:
            try:
                return parse_date(value)
            except (ValueError, OverflowError):
                pass
    return None


ALLOWED_ARTIFACT_TYPES = [OCI_IMAGE_CONFIG_CONTENT_TYPE]
ADDITIONAL_LAYER_CONTENT_TYPES = []


def register_artifact_type(artifact_config_type, artifact_layer_types):
    if artifact_config_type not in ALLOWED_ARTIFACT_TYPES:
        ALLOWED_ARTIFACT_TYPES.append(artifact_config_type)

    for layer_type in artifact_layer_types:
        if layer_type not in ADDITIONAL_LAYER_CONTENT_TYPES:
            ADDITIONAL_LAYER_CONTENT_TYPES.append(layer_type)
