FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN DJANGO_SECRET_KEY=build python manage.py collectstatic --noinput \
    && chmod +x entrypoint.sh \
    && useradd --system --create-home --uid 10001 app

USER app
EXPOSE 8000
