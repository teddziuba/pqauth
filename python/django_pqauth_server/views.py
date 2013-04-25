from django.http import HttpResponse
from django.conf import settings

from pqauth.protocol import server

from django_pqauth_server.key_store import db_key_store
from django_pqauth_server.models import PublicKey
from django_pqauth_server.models import PQAuthSession


def handle_client_hello(request):
    response_plain, response_encrypted = server.get_client_hello_response(
        request.POST, settings.SERVER_KEY, db_key_store, None)

