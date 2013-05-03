from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from pqauth.crypto import load_key_file
from pqauth.crypto import public_key_fingerprint

def load_server_key():
    try:
        key_path = settings.PQAUTH_SERVER_KEY
    except AttributeError:
        msg = "You must set settings.PQUATH_SERVER_KEY"
        raise ImproperlyConfigured(msg)

    key_password = None
    try:
        key_password = settings.PQAUTH_SERVER_KEY_PASSWORD
    except AttributeError:
        pass

    return load_key_file(key_path, key_password)

SERVER_KEY = load_server_key()
SERVER_KEY_FINGERPRINT = public_key_fingerprint(SERVER_KEY)
