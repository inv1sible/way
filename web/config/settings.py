import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=""):
    return os.environ.get(name, default).strip()


def env_list(name, default=""):
    return [item.strip() for item in env(name, default).split(",") if item.strip()]


SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY muss gesetzt sein (siehe .env.example).")

DEBUG = env("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
# Der Reverse Proxy terminiert TLS und meldet das Schema per X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",
    "lookups",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

if env("POSTGRES_HOST"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": env("POSTGRES_HOST"),
            "PORT": env("POSTGRES_PORT", "5432"),
            "NAME": env("POSTGRES_DB", "osint"),
            "USER": env("POSTGRES_USER", "osint"),
            "PASSWORD": env("POSTGRES_PASSWORD"),
        }
    }
else:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "lookups:index"
LOGOUT_REDIRECT_URL = "login"

LANGUAGE_CODE = "de-de"
TIME_ZONE = env("TZ", "Europe/Berlin")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

SESSION_COOKIE_AGE = 14 * 24 * 3600
# Cookies nur über HTTPS; für Tests ohne TLS per DJANGO_SECURE_COOKIES=0 abschaltbar.
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = env("DJANGO_SECURE_COOKIES", "1") == "1"

# Reverse Proxys, deren X-Forwarded-For-Header vertraut wird
TRUSTED_PROXIES = env_list("TRUSTED_PROXIES", "192.168.1.200")

# Login-Sperre (django-axes): nach 3 Fehlversuchen wird die Client-IP für eine Stunde gesperrt.
AXES_FAILURE_LIMIT = 3
AXES_COOLOFF_TIME = 1  # Stunden
AXES_LOCKOUT_PARAMETERS = ["ip_address"]
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = "registration/locked.html"
AXES_CLIENT_IP_CALLABLE = "config.client_ip.client_ip"

CELERY_BROKER_URL = env("REDIS_URL", "redis://redis:6379/0")
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_TIME_LIMIT = 15 * 60
CELERY_TASK_IGNORE_RESULT = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}

# OSINT-Quellen und KI
OSINT_OLLAMA_URL = env("OLLAMA_URL", "http://192.168.1.139:11434")
OSINT_OLLAMA_MODEL = env("OLLAMA_MODEL", "qwen3:8b")
OSINT_SEARXNG_URL = env("SEARXNG_URL", "http://searxng:8080")
OSINT_DEFAULT_REGION = env("DEFAULT_REGION", "DE")
OSINT_ABUSEIPDB_KEY = env("ABUSEIPDB_KEY")
OSINT_GREYNOISE_KEY = env("GREYNOISE_KEY")
