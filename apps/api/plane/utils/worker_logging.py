"""Worker logs never serialize task payloads, return values or exception objects."""

from datetime import datetime, timezone
import json
import logging
import math
import re
from uuid import UUID


AUDIT_MESSAGES = frozenset({
    "Discarded legacy API activity payload",
    "Discarded invalid API activity metadata",
    "Could not persist API activity metadata",
})
EVENT_MESSAGES = AUDIT_MESSAGES | {
    "Task received", "Task succeeded", "Task failed", "Task retry", "Task ignored", "Task rejected",
    "Task internal error", "Task event", "Unregistered task rejected", "Worker error", "Worker event",
}


def task_context(record):
    context = record.__dict__.get("data")
    return context if type(context) is dict else record.args if type(record.args) is dict else {}


def event_message(record):
    message = record.msg if type(record.msg) is str else ""
    if len(message) <= 128 and message in EVENT_MESSAGES:
        return message
    if record.name == "celery.worker.strategy":
        return "Task received"
    if record.name == "celery.app.trace":
        # Match templates, never their rendered arguments or exception text.
        description = task_context(record).get("description")
        descriptions = {"raised unexpected": "Task failed", "raised expected": "Task failed",
                        "ignored": "Task ignored", "rejected": "Task rejected", "INTERNAL ERROR": "Task internal error"}
        if type(description) is str and description in descriptions:
            return descriptions[description]
        for fragment, label in (("succeeded in", "Task succeeded"), ("retry:", "Task retry")):
            if fragment in message[:1024]:
                return label
        return "Task event"
    if "Received unregistered task" in message[:1024]:
        return "Unregistered task rejected"
    return "Worker error" if record.levelno >= logging.ERROR else "Worker event"


def safe_record(record, task_names):
    name = record.name
    if type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", name) is None:
        name = "worker"
    level = record.levelno if record.levelno in (10, 20, 30, 40, 50) else logging.INFO
    safe = logging.LogRecord(name, level, "", 0, event_message(record), (), None)
    if type(record.created) in (int, float) and math.isfinite(record.created) and 0 <= record.created < 253402300800:
        safe.created = record.created
    context = task_context(record)
    identity = context.get("id", record.__dict__.get("task_id"))
    if type(identity) is str and len(identity) in (32, 36):
        try:
            safe.task_id = str(UUID(identity))
        except ValueError:
            pass
    task = context.get("name", record.__dict__.get("task_name"))
    if type(task) is str and task in task_names:
        safe.task_name = task
    return safe


class WorkerLogFilter(logging.Filter):
    def __init__(self, task_names):
        super().__init__()
        self.task_names = task_names

    def filter(self, record):
        # Python3.12+ replaces this handler's record, before any other filters or
        # QueueHandler preparation can serialize extras, traceback or arguments.
        return safe_record(record, self.task_names)


class WorkerJsonFormatter(logging.Formatter):
    def __init__(self, task_names):
        super().__init__()
        self.task_names = task_names

    def format(self, record):
        safe = safe_record(record, self.task_names)
        fields = {"levelname": safe.levelname,
                  "asctime": datetime.fromtimestamp(safe.created, timezone.utc).isoformat(),
                  "name": safe.name, "message": safe.msg}
        for key in ("task_id", "task_name"):
            if key in safe.__dict__:
                fields[key] = safe.__dict__[key]
        return json.dumps(fields)


def configure_worker_logging(task_names, loggers=None):
    if loggers is None:
        loggers = [logging.getLogger(), *[
            logger for logger in logging.Logger.manager.loggerDict.values() if isinstance(logger, logging.Logger)
        ]]
    seen = set()
    for logger in loggers:
        for handler in logger.handlers:
            if id(handler) in seen:
                continue
            seen.add(id(handler))
            handler.filters = [WorkerLogFilter(task_names), *[
                item for item in handler.filters if not isinstance(item, WorkerLogFilter)
            ]]
            handler.setFormatter(WorkerJsonFormatter(task_names))
