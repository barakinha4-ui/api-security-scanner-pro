from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")
if REDIS_URL:
    BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
    RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
else:
    REDIS_HOST = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT = os.getenv("REDIS_PORT", "6379")
    BROKER_URL = os.getenv("CELERY_BROKER_URL", f"redis://{REDIS_HOST}:{REDIS_PORT}/0")
    RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", f"redis://{REDIS_HOST}:{REDIS_PORT}/1")

app = Celery(
    'scanner',
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=['tasks.scan_tasks']
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_default_queue='scanner',
    task_time_limit=300,
    task_soft_time_limit=270,
    worker_concurrency=2,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_ignore_result=False,
    task_routes={
        'scanner.scan_api': {'queue': 'scanner'}
    },
    task_annotations={
        'scanner.scan_api': {'rate_limit': '10/m'}
    }
)

if __name__ == '__main__':
    app.start()
