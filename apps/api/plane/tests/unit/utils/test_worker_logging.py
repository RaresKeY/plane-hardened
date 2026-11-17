import io
import json
import logging
from uuid import uuid4

import pytest
from celery.app import trace

from plane.utils.worker_logging import WorkerJsonFormatter, configure_worker_logging, safe_record


MARKER = "synthetic-queued-body-cookie-return-exception"
TASK = "plane.bgtasks.logger_task.process_logs"


def record(name="celery.worker.strategy", message="Task %(name)s[%(id)s] received", context=None):
    item = logging.LogRecord(name, logging.INFO, __file__, 1, message, (), None)
    item.data = context or {"id": str(uuid4()), "name": TASK, "args": MARKER, "kwargs": MARKER}
    return item


def test_received_payload_extras_and_traceback_are_discarded():
    item = record()
    item.headers = {"Authorization": MARKER}
    item.exc_text = MARKER
    item.stack_info = MARKER
    safe = safe_record(item, {TASK})
    output = json.loads(WorkerJsonFormatter({TASK}).format(safe))
    assert output["message"] == "Task received"
    assert output["task_name"] == TASK and output["task_id"] == item.data["id"]
    assert MARKER not in json.dumps(output)
    assert "data" not in safe.__dict__ and safe.exc_info is None and safe.exc_text is None
    assert item.data["kwargs"] == MARKER  # Handler-local filtering must not mutate another sink's input.


@pytest.mark.parametrize("message,description,event", [
    (trace.LOG_SUCCESS, None, "Task succeeded"),
    (trace.LOG_FAILURE, "raised unexpected", "Task failed"),
    (trace.LOG_FAILURE, "raised expected", "Task failed"),
    (trace.LOG_INTERNAL_ERROR, "INTERNAL ERROR", "Task internal error"),
    (trace.LOG_RETRY, None, "Task retry"),
    (trace.LOG_IGNORED, "ignored", "Task ignored"),
    (trace.LOG_REJECTED, "rejected", "Task rejected"),
])
def test_task_event_categories_survive_without_rendering_input(message, description, event):
    item = record("celery.app.trace", message)
    item.data.update({"return_value": MARKER, "exc": MARKER, "description": description})
    item.args = item.data
    output = json.loads(WorkerJsonFormatter({TASK}).format(safe_record(item, {TASK})))
    assert output["message"] == event and output["task_name"] == TASK
    assert MARKER not in json.dumps(output)


@pytest.mark.parametrize("message", [MARKER, {"body": MARKER}, [MARKER], RuntimeError(MARKER)])
def test_direct_formatter_does_not_render_arbitrary_messages(message):
    item = record("plane.bgtasks.fixture", message)
    item.exc_info = (RuntimeError, RuntimeError(MARKER), None)
    assert MARKER not in WorkerJsonFormatter({TASK}).format(item)


def test_unknown_tasks_and_invalid_identifiers_are_not_logged():
    item = record(context={"id": MARKER, "name": MARKER, "kwargs": MARKER})
    output = json.loads(WorkerJsonFormatter({TASK}).format(item))
    assert "task_id" not in output and "task_name" not in output
    assert MARKER not in json.dumps(output)


@pytest.mark.parametrize("message", ["Discarded legacy API activity payload", "Discarded invalid API activity metadata",
                                      "Could not persist API activity metadata"])
def test_audit_guard_status_messages_remain_visible(message):
    item = record("plane.worker", message)
    output = json.loads(WorkerJsonFormatter({TASK}).format(item))
    assert output["message"] == message


def test_all_installed_handlers_are_sanitized_before_other_filters():
    streams = [io.StringIO(), io.StringIO()]
    logger = logging.Logger("celery.worker.strategy", logging.INFO)
    observations = []

    class Observe(logging.Filter):
        def filter(self, item):
            observations.append("data" in item.__dict__)
            return True

    for stream in streams:
        handler = logging.StreamHandler(stream)
        handler.addFilter(Observe())
        logger.addHandler(handler)
    configure_worker_logging({TASK}, [logger])
    configure_worker_logging({TASK}, [logger])
    logger.handle(record())
    assert observations == [False, False]
    assert all(len(handler.filters) == 2 for handler in logger.handlers)
    for stream in streams:
        output = json.loads(stream.getvalue())
        assert output["message"] == "Task received" and output["task_name"] == TASK
        assert MARKER not in stream.getvalue()


def test_late_task_registration_preserves_identity_without_logging_unknown_names():
    registry = {}
    formatter = WorkerJsonFormatter(registry)
    item = record()
    assert "task_name" not in json.loads(formatter.format(item))
    registry[TASK] = object()
    assert json.loads(formatter.format(item))["task_name"] == TASK
