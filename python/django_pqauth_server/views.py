import json

from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.conf import settings
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.urlresolvers import reverse

from pqauth.protocol import server
from pqauth.protocol import messages

from django_pqauth_server.models import PublicKey
from django_pqauth_server.models import PQAuthSession


class DjangoClientHelloHandler(server.ClientHelloHandler):
    def get_identity(self, key_fingerprint):
        try:
            public_key = PublicKey.objects.get(pk=key_fingerprint)
            return public_key
        except PublicKey.DoesNotExist:
            return None

def _decrypt_request(handler, request):
    try:
        content = handler.decrypt(request.body)
        return content
    except ValueError:
        return None

def _decryption_fail_response():
    error = ("This message was not correctly encrypted "
             "with the server's public key.")
    suggestion = "Check that you are using the correct server public key."
    key_url = reverse(public_key)

    message = json.dumps({"error": error,
                          "suggestion": suggestion,
                          "key_url": key_url})
    return HttpResponseBadRequest(message, content_type="application/json")


def public_key(request):
    # This only exports the public part of the key
    key_text = settings.SERVER_KEY.exportKey(format="OpenSSH")
    return HttpResponse(key_text, mimetype="text/plain")


@require_POST
@csrf_exempt
def handle_client_hello(request):
    handler = DjangoClientHelloHandler(settings.SERVER_KEY)
    hello = _decrypt_request(handler, request)
    if not hello:
        return _decryption_fail_response()

    client_identity, response = handler.handle_step(hello)
    encrypted_response = handler.encrypt(response, client_identity)

    started_session = PQAuthSession(server_guid=response["server_guid"],
                                    client_guid=response["client_guid"],
                                    user=client_identity.user)
    started_session.save()

    return HttpResponse(encrypted_response,
                        mimetype="application/pqauth-encrypted")


@require_POST
@csrf_exempt
def handle_client_confirmation(request):
    handler = server.ClientConfirmationHandler(settings.SERVER_KEY)
    confirmation = _decrypt_request(handler, request)
    if not confirmation:
        return _decryption_fail_response()

    guid = confirmation["server_guid"]

    try:
        started_session = PQAuthSession.objects.get(server_guid=guid)
        sk = messages.get_session_key(started_session.client_guid,
                                      started_session.server_guid)
        started_session.session_key = sk
        started_session.save()
    except PQAuthSession.DoesNotExist:
        pass

    # It's important to return HTTP 200 here whether or no the confirmation
    # succeeded. If you return an error on an unrecognized server_guid, it
    # could help an attacker brute-force the session keys
    # (by notifying them that they've got half of it)

    return HttpResponse()
