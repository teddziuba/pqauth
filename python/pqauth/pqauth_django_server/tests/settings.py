import os

DIRNAME = os.path.dirname(__file__)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3"
    }
}

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "pqauth.pqauth_django_server"
)

SECRET_KEY = "chicken butt"

PQAUTH_SERVER_KEY = os.path.join(DIRNAME, "server.key")

ROOT_URLCONF = "pqauth.pqauth_django_server.urls"


TEST_CLIENT_KEY = os.path.join(DIRNAME, "client.key")
TEST_EVIL_KEY = os.path.join(DIRNAME, "evil.key")
