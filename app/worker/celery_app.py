from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery("fakeapp", broker=settings.redis_url, include=["app.worker.tasks", "app.worker.maintenance"])

celery_app.conf.update(
    # Solo JSON: nunca pickle (pickle permite ejecutar código al deserializar).
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # El resultado no viaja por Celery; lo guardamos nosotros en app/store.py.
    task_ignore_result=True,
    # Si el worker se cae a medio análisis, la tarea vuelve a la cola.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Un análisis que se cuelga se cancela (soft) y, si no obedece, se mata (hard).
    task_soft_time_limit=settings.analysis_time_limit_seconds,
    task_time_limit=settings.analysis_time_limit_seconds + 30,
    broker_connection_retry_on_startup=True,
    # Limpieza diaria (la dispara el servicio `beat`): 03:30 UTC.
    timezone="UTC",
    beat_schedule={
        "purge-expired": {"task": "purge_expired", "schedule": crontab(hour=3, minute=30)},
    },
)
