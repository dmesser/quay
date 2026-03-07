import hashlib
import json

import pytest

from image.docker.schema1 import DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE
from image.oci import parse_annotation_created_datetime, register_artifact_type
from image.oci.manifest import MalformedOCIManifest, OCIManifest
from image.shared.schemautil import ContentRetrieverForTesting
from util.bytes import Bytes

SAMPLE_MANIFEST = """{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"""

SAMPLE_MANIFEST2 = """{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
      "annotations": {
        "com.example.layerkey1": "value1",
        "com.example.layerkey2": "value2"
      }
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"""
SAMPLE_MANIFEST2 = """{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
      "annotations": {
        "com.example.layerkey1": "value1",
        "com.example.layerkey2": "value2"
      }
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"""

SAMPLE_REMOTE_MANIFEST = """{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654,
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    },
    {
      "mediaType": "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
      "size": 16724,
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
      "urls": ["https://foo/bar"]
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 73109,
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"""


def test_parse_basic_manifest():
    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_MANIFEST))
    assert not manifest.is_manifest_list
    assert (
        manifest.digest == "sha256:855b4e9ce4a4e5121dbc51a4f7ebfe7c2d6bcd16b159e754224f44573cfed5c2"
    )

    assert manifest.blob_digests == [
        "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
        "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
        "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    ]

    assert manifest.local_blob_digests == manifest.blob_digests

    assert len(manifest.filesystem_layers) == 3
    assert (
        str(manifest.leaf_filesystem_layer.digest)
        == "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    )

    assert not manifest.has_remote_layer
    assert manifest.has_legacy_image
    assert manifest.annotations == {"com.example.key1": "value1", "com.example.key2": "value2"}


def test_parse_basic_remote_manifest():
    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_REMOTE_MANIFEST))
    assert not manifest.is_manifest_list
    assert (
        manifest.digest == "sha256:dd18ed87a00474aff683cee7160771e043f1f0eadd780232715bc0678a984a5e"
    )

    assert manifest.blob_digests == [
        "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
        "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
        "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    ]

    assert manifest.local_blob_digests == [
        "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
        "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    ]

    assert len(manifest.filesystem_layers) == 3
    assert (
        str(manifest.leaf_filesystem_layer.digest)
        == "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
    )

    assert manifest.has_remote_layer

    assert not manifest.has_legacy_image
    assert not manifest.get_legacy_image_ids(None)


def test_get_schema1_manifest():
    retriever = ContentRetrieverForTesting.for_config(
        {
            "config": {
                "Labels": {
                    "foo": "bar",
                },
            },
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [
                {"created": "2018-04-03T18:37:09.284840891Z", "created_by": "foo"},
                {"created": "2018-04-12T18:37:09.284840891Z", "created_by": "bar"},
                {"created": "2018-04-03T18:37:09.284840891Z", "created_by": "foo"},
            ],
            "architecture": "amd64",
            "os": "linux",
        },
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
        7023,
    )

    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_MANIFEST))
    assert manifest.get_manifest_labels(retriever) == {
        "com.example.key1": "value1",
        "com.example.key2": "value2",
        "foo": "bar",
    }

    schema1 = manifest.get_schema1_manifest("somenamespace", "somename", "sometag", retriever)
    assert schema1 is not None
    assert schema1.media_type == DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE
    assert set(schema1.local_blob_digests) == (
        set(manifest.local_blob_digests)
        - {"sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"}
    )
    assert len(schema1.layers) == 3

    via_convert = manifest.convert_manifest(
        [schema1.media_type], "somenamespace", "somename", "sometag", retriever
    )
    assert via_convert.digest == schema1.digest


def test_get_schema1_manifest_missing_history():
    retriever = ContentRetrieverForTesting.for_config(
        {
            "config": {
                "Labels": {
                    "foo": "bar",
                },
                "Cmd": ["dosomething"],
            },
            "rootfs": {"type": "layers", "diff_ids": []},
            "architecture": "amd64",
            "os": "linux",
        },
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
        7023,
    )

    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_MANIFEST))
    assert manifest.get_manifest_labels(retriever) == {
        "com.example.key1": "value1",
        "com.example.key2": "value2",
        "foo": "bar",
    }

    schema1 = manifest.get_schema1_manifest("somenamespace", "somename", "sometag", retriever)
    assert schema1 is not None
    assert schema1.media_type == DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE
    assert set(schema1.local_blob_digests) == (
        set(manifest.local_blob_digests)
        - {"sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"}
    )
    assert len(schema1.layers) == 3

    via_convert = manifest.convert_manifest(
        [schema1.media_type], "somenamespace", "somename", "sometag", retriever
    )
    assert via_convert.digest == schema1.digest

    final_layer = schema1.leaf_layer
    assert final_layer.v1_metadata.command == '[["dosomething"]]'


def test_get_schema1_manifest_incorrect_history():
    retriever = ContentRetrieverForTesting.for_config(
        {
            "config": {
                "Labels": {
                    "foo": "bar",
                },
            },
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [
                {"created": "2018-04-03T18:37:09.284840891Z", "created_by": "foo"},
                {"created": "2018-04-03T18:37:09.284840891Z", "created_by": "foo"},
            ],
            "architecture": "amd64",
            "os": "linux",
        },
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
        7023,
    )

    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_MANIFEST))
    assert manifest.get_manifest_labels(retriever) == {
        "com.example.key1": "value1",
        "com.example.key2": "value2",
        "foo": "bar",
    }

    with pytest.raises(MalformedOCIManifest):
        manifest.get_schema1_manifest("somenamespace", "somename", "sometag", retriever)


def test_validate_helm_oci_manifest():
    manifest_bytes = """{
      "schemaVersion":2,
      "config":{
        "mediaType":"application/vnd.cncf.helm.config.v1+json",
        "digest":"sha256:65a07b841ece031e6d0ec5eb948eacb17aa6d7294cdeb01d5348e86242951487",
        "size":141
      },
    "layers": [
      {
        "mediaType":"application/tar+gzip",
        "digest":"sha256:d84c9c29e0899862a0fa0f73da4d9f8c8c38e2da5d3258764aa7ba74bb914718",
        "size":3562
       }
      ]
    }"""

    HELM_CHART_CONFIG_TYPE = "application/vnd.cncf.helm.config.v1+json"
    HELM_CHART_LAYER_TYPES = ["application/tar+gzip"]
    register_artifact_type(HELM_CHART_CONFIG_TYPE, HELM_CHART_LAYER_TYPES)
    manifest = OCIManifest(Bytes.for_string_or_unicode(manifest_bytes))


INVALID_LAYER_SIZE_MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 7023,
            "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 32654,
                "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": -1,
                "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 73109,
                "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
            },
        ],
        "annotations": {"com.example.key1": "value1", "com.example.key2": "value2"},
    }
).encode("utf-8")


def test_invalid_layer_size_manifest():
    with pytest.raises(MalformedOCIManifest, match="invalid layer size"):
        OCIManifest(Bytes.for_string_or_unicode(INVALID_LAYER_SIZE_MANIFEST))


MANIFEST_WITH_LAYER_SIZE_0 = json.dumps(
    {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 7023,
            "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 32654,
                "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 0,
                "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 73109,
                "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
            },
        ],
        "annotations": {"com.example.key1": "value1", "com.example.key2": "value2"},
    }
).encode()


def test_manifest_with_layer_size_0():
    digest = "sha256:" + hashlib.sha256(MANIFEST_WITH_LAYER_SIZE_0).hexdigest()
    manifest = OCIManifest(Bytes.for_string_or_unicode(MANIFEST_WITH_LAYER_SIZE_0))
    assert manifest.digest == digest
    assert manifest.blob_digests == [
        "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
        "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    ]


def test_manifest_layer_annotations():
    manifest = OCIManifest(Bytes.for_string_or_unicode(SAMPLE_MANIFEST2))
    assert manifest.annotations == {"com.example.key1": "value1", "com.example.key2": "value2"}

    for layer in manifest.filesystem_layers:
        assert hasattr(layer, "annotations")
        if layer.annotations:
            assert layer.annotations == {
                "com.example.layerkey1": "value1",
                "com.example.layerkey2": "value2",
            }


def _build_oci_manifest_with_annotation(annotation_key, annotation_value, config_created=None):
    """Helper: builds an OCI manifest JSON with a given annotation and optional config created."""
    config_obj = {
        "config": {"Labels": {}},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:abc"]},
        "history": [],
    }
    if config_created:
        config_obj["created"] = config_created

    config_bytes = json.dumps(config_obj).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    manifest_dict = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 100,
                "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            }
        ],
        "annotations": {annotation_key: annotation_value},
    }
    manifest_bytes = json.dumps(manifest_dict).encode("utf-8")
    retriever = ContentRetrieverForTesting({config_digest: config_bytes.decode("utf-8")})
    manifest = OCIManifest(Bytes.for_string_or_unicode(manifest_bytes))
    return manifest, retriever


def test_get_image_created_datetime_from_oci_annotation():
    """org.opencontainers.image.created annotation is preferred over config created."""
    manifest, retriever = _build_oci_manifest_with_annotation(
        "org.opencontainers.image.created",
        "2025-06-15T12:00:00Z",
        config_created="2024-01-01T00:00:00Z",
    )
    result = manifest.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2025
    assert result.month == 6
    assert result.day == 15


def test_get_image_created_datetime_label_schema_fallback():
    """org.label-schema.build-date annotation is used as fallback."""
    manifest, retriever = _build_oci_manifest_with_annotation(
        "org.label-schema.build-date",
        "2023-11-20T08:30:00Z",
    )
    result = manifest.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2023
    assert result.month == 11


def test_get_image_created_datetime_falls_back_to_config():
    """Without annotation, falls back to config blob created field."""
    manifest, retriever = _build_oci_manifest_with_annotation(
        "com.example.unrelated",
        "some-value",
        config_created="2024-03-10T15:00:00Z",
    )
    result = manifest.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2024
    assert result.month == 3


def test_get_image_created_datetime_invalid_annotation_falls_back():
    """Invalid annotation date falls back to config."""
    manifest, retriever = _build_oci_manifest_with_annotation(
        "org.opencontainers.image.created",
        "not-a-date",
        config_created="2024-05-01T10:00:00Z",
    )
    result = manifest.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2024
    assert result.month == 5


class TestParseAnnotationCreatedDatetime:
    def test_oci_created_annotation(self):
        result = parse_annotation_created_datetime(
            {"org.opencontainers.image.created": "2025-01-15T10:30:00Z"}
        )
        assert result is not None
        assert result.year == 2025

    def test_label_schema_build_date(self):
        result = parse_annotation_created_datetime(
            {"org.label-schema.build-date": "2023-06-01T00:00:00Z"}
        )
        assert result is not None
        assert result.year == 2023

    def test_oci_preferred_over_label_schema(self):
        result = parse_annotation_created_datetime(
            {
                "org.opencontainers.image.created": "2025-01-01T00:00:00Z",
                "org.label-schema.build-date": "2020-01-01T00:00:00Z",
            }
        )
        assert result is not None
        assert result.year == 2025

    def test_empty_annotations(self):
        assert parse_annotation_created_datetime({}) is None

    def test_no_matching_keys(self):
        assert parse_annotation_created_datetime({"com.example.key": "value"}) is None

    def test_invalid_date_string(self):
        assert (
            parse_annotation_created_datetime(
                {"org.opencontainers.image.created": "not-a-valid-date"}
            )
            is None
        )

    def test_empty_value_ignored(self):
        assert parse_annotation_created_datetime({"org.opencontainers.image.created": ""}) is None
