import json

from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.views.decorators.http import require_POST
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt

from pqauth.crypto import rsa_decrypt
from pqauth.crypto import rsa_encrypt
from pqauth.crypto import random_guid

from pqauth.pqauth_django_server.keys import SERVER_KEY
from pqauth.pqauth_django_server.keys import SERVER_KEY_FINGERPRINT
from pqauth.pqauth_django_server.models import PublicKey
from pqauth.pqauth_django_server.models import PQAuthSession


def encrypted_json_post(view_func):
    def inner(request, *args, **kwargs):
        try:
            decrypted_body = rsa_decrypt(request.body, SERVER_KEY)
            request.decrypted_json = json.loads(decrypted_body)
            return view_func(request, *args, **kwargs)
        except ValueError:
            msg = ("This endpoint expects a JSON object, "
                   "encrypted with the server's public RSA key")
            return HttpResponseBadRequest(msg)
    return csrf_exempt(require_POST(inner))


@require_safe
def public_key(_):
    # This only exports the public part of the key
    key_text = SERVER_KEY.exportKey(format="OpenSSH")
    return HttpResponse(key_text, mimetype="text/plain")


@encrypted_json_post
def hello(request):
    client_hello = request.decrypted_json
    try:
        client_key = PublicKey.objects.get(
            fingerprint=client_hello["client_key_fingerprint"])
    except PublicKey.DoesNotExist:
        return HttpResponseForbidden("Unknown client: %s" %
                                     client_hello["client_key_fingerprint"])

    response = {"client_guid": client_hello["client_guid"],
                "server_guid": random_guid(),
                "expires": None,
                "server_key_fingerprint": SERVER_KEY_FINGERPRINT}

    started_session = PQAuthSession(server_guid=response["server_guid"],
                                    client_guid=response["client_guid"],
                                    user=client_key.user)
    started_session.save()

    encrypted_response = rsa_encrypt(json.dumps(response),
                                     client_key.public_key)

    return HttpResponse(encrypted_response,
                        mimetype="application/pqauth-encrypted")


@encrypted_json_post
def confirm(request):
    confirm = request.decrypted_json
    guid = confirm["server_guid"]

    try:
        started_session = PQAuthSession.objects.get(server_guid=guid)
        started_session.session_key = "%s:%s" % (started_session.client_guid,
                                                 started_session.server_guid)
        started_session.save()
    except PQAuthSession.DoesNotExist:
        pass

    # It's important to return HTTP 200 here whether or no the confirmation
    # succeeded. If you return an error on an unrecognized server_guid, it
    # could help an attacker brute-force the session keys
    # (by notifying them that they've got half of it)

    return HttpResponse()
