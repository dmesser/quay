import json

import pytest

from image.oci.index import MalformedIndex, OCIIndex, OCIIndexBuilder
from image.oci.test.testdata import (
    OCI_IMAGE_INDEX_MANIFEST,
    OCI_IMAGE_INDEX_MANIFEST_WITH_ARTIFACT_TYPE_AND_SUBJECT,
    OCI_IMAGE_INDEX_MANIFEST_WITHOUT_AMD,
    OCI_IMAGE_WITH_ARTIFACT_TYPES_AND_ANNOTATIONS,
)
from image.shared.schemas import parse_manifest_from_bytes
from image.shared.schemautil import ContentRetrieverForTesting
from util.bytes import Bytes


def test_parse_basic_index():
    index = OCIIndex(Bytes.for_string_or_unicode(OCI_IMAGE_INDEX_MANIFEST))
    assert index.is_manifest_list
    assert index.digest == "sha256:6416299892584b515393076863b75f192ca6cf98583d83b8e583ec3b6f2a8a5e"
    assert index.local_blob_digests == []
    assert index.child_manifest_digests() == [
        "sha256:31dd947a0acb5d8b840dc0de40a74f336e08cb0e17ba951c2faaea6374c1a0f3",
        "sha256:4eca3b97fcd88a47c6454d0cb9ff59aeb4baeca332387e87421b2302bfc724e6",
        "sha256:dacec655f2712b6f5eabc007b154959bba7add6aafdcab883e314f16e491f9d3",
    ]
    assert (
        index.amd64_linux_manifest_digest
        == "sha256:31dd947a0acb5d8b840dc0de40a74f336e08cb0e17ba951c2faaea6374c1a0f3"
    )


def test_config_missing_required():
    valid_index = json.loads(OCI_IMAGE_INDEX_MANIFEST)
    valid_index.pop("schemaVersion")

    with pytest.raises(MalformedIndex):
        OCIIndex(Bytes.for_string_or_unicode(json.dumps(valid_index)))


def test_invalid_index():
    with pytest.raises(MalformedIndex):
        OCIIndex(Bytes.for_string_or_unicode("{}"))


def test_index_without_amd():
    index = OCIIndex(Bytes.for_string_or_unicode(OCI_IMAGE_INDEX_MANIFEST_WITHOUT_AMD))
    assert index.is_manifest_list
    assert index.digest == "sha256:a0ed0f2b3949bc731063320667062307faf4245f6872dc5bc98ee6ea5443f169"
    assert index.local_blob_digests == []
    assert index.child_manifest_digests() == [
        "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
        "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
    ]
    assert index.amd64_linux_manifest_digest is None


def test_index_with_artifact_type_and_subject():
    index = OCIIndex(
        Bytes.for_string_or_unicode(OCI_IMAGE_INDEX_MANIFEST_WITH_ARTIFACT_TYPE_AND_SUBJECT)
    )
    assert index.is_manifest_list
    assert index.digest == "sha256:e2469184de432b3f6cb81d3e5ab0a4b77bf7d4008db3e7f3c3ba2f36e11cef5b"
    assert index.local_blob_digests == []
    assert index.child_manifest_digests() == [
        "sha256:31dd947a0acb5d8b840dc0de40a74f336e08cb0e17ba951c2faaea6374c1a0f3",
        "sha256:4eca3b97fcd88a47c6454d0cb9ff59aeb4baeca332387e87421b2302bfc724e6",
        "sha256:dacec655f2712b6f5eabc007b154959bba7add6aafdcab883e314f16e491f9d3",
    ]
    assert (
        index.amd64_linux_manifest_digest
        == "sha256:31dd947a0acb5d8b840dc0de40a74f336e08cb0e17ba951c2faaea6374c1a0f3"
    )
    assert index.artifact_type == "application/some.thing"
    assert (
        index.subject.digest
        == "sha256:6416299892584b515393076863b75f192ca6cf98583d83b8e583ec3b6f2a8a5e"
    )


def test_index_builder_with_artifact_type_and_annotations():
    index_builder = OCIIndexBuilder()
    parsed_manifest = parse_manifest_from_bytes(
        Bytes.for_string_or_unicode(OCI_IMAGE_WITH_ARTIFACT_TYPES_AND_ANNOTATIONS),
        "application/vnd.oci.image.manifest.v1+json",
    )

    index_builder.add_manifest_for_referrers_index(parsed_manifest)
    referrers_index = index_builder.build()

    assert referrers_index.is_manifest_list
    assert referrers_index.annotations

    manifests = referrers_index.manifest_dict["manifests"]
    for manifest in manifests:
        assert manifest.get("artifactType") is not None
        assert manifest.get("annotations") is not None


def _build_index_with_annotations(annotations):
    """Helper: builds a minimal OCI index with the given annotations dict."""
    index_dict = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 1000,
                "digest": "sha256:aaaa",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
        "annotations": annotations,
    }
    return OCIIndex(Bytes.for_string_or_unicode(json.dumps(index_dict)))


def test_index_get_image_created_datetime_from_annotation():
    """OCI index with org.opencontainers.image.created returns the annotation date."""
    index = _build_index_with_annotations(
        {"org.opencontainers.image.created": "2025-03-01T09:00:00Z"}
    )
    retriever = ContentRetrieverForTesting()
    result = index.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2025
    assert result.month == 3
    assert result.day == 1


def test_index_get_image_created_datetime_label_schema():
    """OCI index with org.label-schema.build-date returns that date."""
    index = _build_index_with_annotations({"org.label-schema.build-date": "2022-12-25T18:30:00Z"})
    retriever = ContentRetrieverForTesting()
    result = index.get_image_created_datetime(retriever)
    assert result is not None
    assert result.year == 2022
    assert result.month == 12


def test_index_get_image_created_datetime_no_annotation():
    """OCI index without created annotation returns None."""
    index = _build_index_with_annotations({"com.example.key": "value"})
    retriever = ContentRetrieverForTesting()
    result = index.get_image_created_datetime(retriever)
    assert result is None


def test_index_get_image_created_datetime_empty_annotations():
    """OCI index with empty annotations returns None."""
    index_dict = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 1000,
                "digest": "sha256:aaaa",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    index = OCIIndex(Bytes.for_string_or_unicode(json.dumps(index_dict)))
    retriever = ContentRetrieverForTesting()
    result = index.get_image_created_datetime(retriever)
    assert result is None
