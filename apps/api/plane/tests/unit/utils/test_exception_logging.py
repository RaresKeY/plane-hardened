import json
import logging

import pytest
from django.test import override_settings

from plane.utils.exception_logger import log_exception


MARKER = "synthetic-private-exception-body-token-url"


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("warning", [False, True])
def test_exception_logs_keep_failure_category_without_input_or_traceback(caplog, debug, warning):
    with override_settings(DEBUG=debug), caplog.at_level(logging.DEBUG, logger="plane.exception"):
        try:
            raise ValueError(MARKER)
        except ValueError as error:
            assert log_exception(error, warning=warning) is None
    rows = [record for record in caplog.records if record.name == "plane.exception"]
    assert len(rows) == 1
    record = rows[0]
    assert record.levelno == (logging.WARNING if warning else logging.ERROR)
    assert record.exception_type == "ValueError"
    assert record.exc_info is None and record.exc_text is None and record.stack_info is None
    assert MARKER not in json.dumps(record.__dict__, default=str)


@pytest.mark.parametrize("warning", [False, True])
def test_exception_and_cause_are_never_rendered(caplog, warning):
    class NeverRender(ValueError):
        def __str__(self):
            raise AssertionError("Exception text must not be evaluated")

        def __repr__(self):
            raise AssertionError("Exception repr must not be evaluated")

    error = NeverRender(MARKER)
    error.__cause__ = RuntimeError(MARKER)
    with caplog.at_level(logging.INFO, logger="plane.exception"):
        log_exception(error, warning=warning)
    record = caplog.records[-1]
    assert record.exception_type == "NeverRender"
    assert MARKER not in json.dumps(record.__dict__)


@pytest.mark.parametrize("name", ["bad\nname", "bad/name", "x" * 65])
def test_invalid_exception_type_uses_fixed_category(caplog, name):
    error = type(name, (Exception,), {})(MARKER)
    with caplog.at_level(logging.INFO, logger="plane.exception"):
        log_exception(error)
    assert caplog.records[-1].exception_type == "Exception"


@pytest.mark.parametrize("kind,status,code", [
    ("ValidationError", 400, "VALIDATION_ERROR"),
    ("ObjectDoesNotExist", 404, "OBJECT_DOES_NOT_EXIST"),
    ("KeyError", 400, "KEY_ERROR"),
])
def test_api_exception_branches_omit_error_values_and_preserve_response(caplog, monkeypatch, kind, status, code):
    from plane.api.views import base

    error_class = KeyError if kind == "KeyError" else getattr(base, kind)
    error = error_class(MARKER)

    def raise_error(*_):
        raise error

    monkeypatch.setattr(base.ModelViewSet, "handle_exception", raise_error)
    with caplog.at_level(logging.INFO, logger="plane.api"):
        response = base.BaseViewSet().handle_exception(error)
    assert response.status_code == status
    record = caplog.records[-1]
    assert record.error_code == code
    assert MARKER not in json.dumps(record.__dict__, default=str)
    assert record.exc_info is None


@pytest.mark.parametrize("failure", [False, True])
def test_email_verification_errors_never_log_address_cache_key_or_error(caplog, monkeypatch, failure):
    from types import SimpleNamespace
    from plane.app.views.user import base

    view = base.UserEndpoint()
    monkeypatch.setattr(view, "get_object", lambda: SimpleNamespace(id="synthetic-user-id"))
    monkeypatch.setattr(view, "_validate_new_email", lambda *_: None)
    request = SimpleNamespace(data={"email": MARKER + "@fixture.invalid", "code": "123456"})
    if failure:
        def fail(*_, **__):
            raise RuntimeError(MARKER)

        monkeypatch.setattr(base.cache, "set", fail)
    else:
        monkeypatch.setattr(base.cache, "get", lambda *_: None)
    with caplog.at_level(logging.INFO, logger="plane"):
        response = (view.generate_email_verification_code(request) if failure else view.update_email(request))
    assert response.status_code == 400
    assert caplog.records
    assert MARKER not in caplog.text and "magic_email_update_" not in caplog.text


def test_rejected_webhook_url_does_not_enter_logs(caplog, monkeypatch):
    from rest_framework.exceptions import ValidationError
    from plane.app.serializers import webhook

    def fail(*_, **__):
        raise ValueError(MARKER)

    monkeypatch.setattr(webhook, "validate_url", fail)
    with caplog.at_level(logging.WARNING, logger=webhook.__name__), pytest.raises(ValidationError) as error:
        webhook.WebhookSerializer()._validate_webhook_url("https://fixture.invalid/?token=" + MARKER)
    assert "Invalid or disallowed" in str(error.value)
    assert MARKER not in caplog.text


@pytest.mark.parametrize("failure", [False, True])
def test_presigned_post_retains_valid_result_without_printing_client_errors(caplog, capsys, failure):
    from unittest.mock import Mock
    from botocore.exceptions import ClientError
    from plane.settings.storage import S3Storage

    storage = object.__new__(S3Storage)
    storage.signed_url_expiration = 60
    storage.aws_storage_bucket_name = "fixture"
    storage.s3_client = Mock()
    expected = {"url": "https://fixture.invalid", "fields": {"key": "valid"}}
    storage.s3_client.generate_presigned_post.return_value = expected
    if failure:
        storage.s3_client.generate_presigned_post.side_effect = ClientError(
            {"Error": {"Code": "FixtureError", "Message": MARKER}}, "PutObject")
    with caplog.at_level(logging.INFO, logger="plane.exception"):
        result = storage.generate_presigned_post("valid", "image/png", 1024)
    assert result is (None if failure else expected)
    assert storage.s3_client.generate_presigned_post.call_args.kwargs["Key"] == "valid"
    output = capsys.readouterr()
    assert MARKER not in output.out + output.err + caplog.text


def test_notification_failure_does_not_print_exception_input(caplog, capsys, monkeypatch):
    from unittest.mock import Mock
    from plane.bgtasks import notification_task

    monkeypatch.setattr(notification_task.ProjectMember.objects, "filter", Mock(side_effect=RuntimeError(MARKER)))
    with caplog.at_level(logging.INFO, logger="plane.exception"):
        assert notification_task.notifications.run("issue.created", "issue", "project", "actor", None,
                                                  None, None, None) is None
    output = capsys.readouterr()
    assert MARKER not in output.out + output.err + caplog.text


def test_relation_failure_does_not_print_input_or_interrupt_soft_delete(caplog, capsys, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from django.db.models import CASCADE
    from plane.bgtasks import deletion_task

    relation = SimpleNamespace(one_to_many=True, one_to_one=False, auto_created=True, concrete=False,
                               get_accessor_name=lambda: "related", on_delete=CASCADE)
    instance = SimpleNamespace(_meta=SimpleNamespace(get_fields=lambda: [relation]), deleted_at=None,
                               related=Mock(side_effect=RuntimeError(MARKER)), save=Mock())
    model = SimpleNamespace(all_objects=Mock(), DoesNotExist=type("MissingFixture", (Exception,), {}))
    model.all_objects.get.return_value = instance
    monkeypatch.setattr(deletion_task.apps, "get_model", lambda *_: model)
    with caplog.at_level(logging.INFO, logger="plane.exception"):
        deletion_task.soft_delete_related_objects.run("db", "Fixture", "id")
    instance.save.assert_called_once()
    assert instance.deleted_at is not None
    output = capsys.readouterr()
    assert MARKER not in output.out + output.err + caplog.text


def test_webhook_task_debug_error_does_not_print_input(caplog, capsys, monkeypatch):
    from unittest.mock import Mock
    from plane.bgtasks import webhook_task

    monkeypatch.setattr(webhook_task.Webhook.objects, "filter", Mock(side_effect=RuntimeError(MARKER)))
    with override_settings(DEBUG=True), caplog.at_level(logging.INFO, logger="plane.exception"):
        webhook_task.webhook_activity.run("issue", "updated", None, None, None, "actor", "workspace",
                                         "http://fixture.invalid", "issue", None, None)
    output = capsys.readouterr()
    assert MARKER not in output.out + output.err + caplog.text


@pytest.mark.parametrize("operation", ["convert", "models", "clear"])
def test_filter_migration_error_does_not_log_stored_values(caplog, monkeypatch, operation):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from plane.utils.filters import filter_migrations as migrations

    model = SimpleNamespace(objects=Mock())
    converter = Mock()
    converter.convert.side_effect = ValueError(MARKER)
    if operation == "convert":
        rows = Mock()
        rows.count.return_value = 1
        rows.__iter__ = Mock(return_value=iter([SimpleNamespace(id="id", filters={"private": MARKER})]))
        model.objects.exclude.return_value.filter.return_value = rows
    elif operation == "models":
        monkeypatch.setattr(migrations, "migrate_single_model_filters", Mock(side_effect=ValueError(MARKER)))
    else:
        model.objects.exclude.side_effect = ValueError(MARKER)
    with caplog.at_level(logging.INFO, logger=migrations.logger.name):
        if operation == "convert":
            assert migrations.migrate_single_model_filters(model, "Fixture", converter) == (0, 1)
        elif operation == "models":
            result = migrations.migrate_models_filters_to_rich_filters({"Fixture": model}, converter)
            assert result == {"Fixture": (0, 1)}
        else:
            assert migrations.clear_models_rich_filters({"Fixture": model}) == {"Fixture": 0}
    assert MARKER not in caplog.text
