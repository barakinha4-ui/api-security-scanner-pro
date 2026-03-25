#!/bin/bash
echo "Ligando Celery Worker em segundo plano..."
celery -A celery_app worker --loglevel=info &

echo "Ligando Servidor Web FastAPI..."
uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
