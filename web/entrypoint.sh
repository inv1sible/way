#!/bin/sh
set -e

python manage.py migrate --noinput

if [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
    python manage.py createsuperuser --noinput 2>/dev/null || true
fi

exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 \
    --worker-class gthread --workers 2 --threads 8 --worker-tmp-dir /dev/shm --access-logfile -
