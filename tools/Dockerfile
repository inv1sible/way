FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Die eigentlichen Werkzeuge: whois, dig (bind9-dnsutils), openssl, curl
RUN apt-get update \
    && apt-get install -y --no-install-recommends whois bind9-dnsutils openssl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10002 tools

WORKDIR /srv
COPY app.py test_app.py ./
USER tools
EXPOSE 8000
CMD ["python", "app.py"]
