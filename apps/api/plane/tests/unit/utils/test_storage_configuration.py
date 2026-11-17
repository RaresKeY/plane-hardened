from unittest.mock import Mock

import pytest

from plane.settings import storage


class UntrustedRequest:
    @property
    def scheme(self):
        raise AssertionError("Storage endpoint must not read a request scheme")

    def get_host(self):
        raise AssertionError("Storage endpoint must not read a request Host")


@pytest.fixture
def configured_storage(monkeypatch):
    for key, value in {"USE_MINIO": "1", "AWS_S3_ENDPOINT_URL": "http://storage.fixture.invalid:9000",
                       "WEB_URL": "https://plane.fixture.invalid:8443", "AWS_REGION": "us-east-1"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PUBLIC_S3_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("MINIO_ENDPOINT_URL", raising=False)
    factory = Mock()
    monkeypatch.setattr(storage.boto3, "client", factory)
    return factory


@pytest.mark.parametrize("mode,expected", [
    ("public", "https://plane.fixture.invalid:8443"),
    ("server", "http://storage.fixture.invalid:9000"),
    ("background", "http://storage.fixture.invalid:9000"),
])
def test_minio_endpoint_comes_from_configured_role_not_request(configured_storage, mode, expected):
    request = None if mode == "background" else UntrustedRequest()
    storage.S3Storage(request=request, is_server=mode == "server")
    assert configured_storage.call_args.kwargs["endpoint_url"] == expected


def test_explicit_public_gateway_overrides_web_origin(configured_storage, monkeypatch):
    monkeypatch.setenv("PUBLIC_S3_ENDPOINT_URL", "https://uploads.fixture.invalid")
    storage.S3Storage(request=UntrustedRequest())
    assert configured_storage.call_args.kwargs["endpoint_url"] == "https://uploads.fixture.invalid"


def test_aws_default_service_endpoint_and_server_argument_remain_supported(configured_storage, monkeypatch):
    monkeypatch.setenv("USE_MINIO", "0")
    monkeypatch.delenv("AWS_S3_ENDPOINT_URL")
    storage.S3Storage(request=UntrustedRequest(), is_server=True)
    assert configured_storage.call_args.kwargs["endpoint_url"] is None


@pytest.mark.parametrize("endpoint", [None, "", "ftp://fixture.invalid", "https://user:secret@fixture.invalid",
                                     "https://fixture.invalid/?token=secret", "https://fixture.invalid/#secret",
                                     "https://fixture.invalid/prefix", "https://fixture.invalid:65536",
                                     "https://fixture.invalid:0", "https://fixture.invalid/\nsecret"])
def test_invalid_storage_configuration_fails_before_client_creation(configured_storage, monkeypatch, endpoint):
    if endpoint is None:
        monkeypatch.delenv("WEB_URL")
    else:
        monkeypatch.setenv("WEB_URL", endpoint)
    with pytest.raises(ValueError) as error:
        storage.S3Storage(request=UntrustedRequest())
    assert "secret" not in str(error.value)
    configured_storage.assert_not_called()


@pytest.mark.parametrize("server,host", [(False, "plane.fixture.invalid"), (True, "storage.fixture.invalid")])
def test_real_sdk_signs_upload_and_download_for_configured_origin_without_network(monkeypatch, server, host):
    from urllib.parse import urlsplit

    for key, value in {"USE_MINIO": "1", "AWS_S3_ENDPOINT_URL": "http://storage.fixture.invalid:9000",
                       "WEB_URL": "https://plane.fixture.invalid", "AWS_REGION": "us-east-1",
                       "AWS_ACCESS_KEY_ID": "synthetic-fixture-access-key",
                       "AWS_SECRET_ACCESS_KEY": "synthetic-fixture-secret-not-production",
                       "AWS_S3_BUCKET_NAME": "fixture", "AWS_EC2_METADATA_DISABLED": "true"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PUBLIC_S3_ENDPOINT_URL", raising=False)
    send = Mock(side_effect=AssertionError("Presigning must not send an HTTP request"))
    monkeypatch.setattr("botocore.httpsession.URLLib3Session.send", send)
    instance = storage.S3Storage(request=UntrustedRequest(), is_server=server)
    post = instance.generate_presigned_post("fixture.png", "image/png", 1024, expiration=30)
    assert urlsplit(post["url"]).hostname == host
    assert post["fields"]["key"] == "fixture.png" and post["fields"]["x-amz-signature"]
    download = instance.generate_presigned_url("fixture.png", expiration=30)
    assert urlsplit(download).hostname == host and "X-Amz-Signature=" in download
    send.assert_not_called()
