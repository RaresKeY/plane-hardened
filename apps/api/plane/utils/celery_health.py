"""Scheduler-loop liveness; normal database scheduling semantics are preserved."""

from django_celery_beat.schedulers import DatabaseScheduler

from plane.utils.runtime_health import beat_heartbeat


class HeartbeatDatabaseScheduler(DatabaseScheduler):
    def tick(self, *args, **kwargs):
        delay = super().tick(*args, **kwargs)
        beat_heartbeat()
        return delay
