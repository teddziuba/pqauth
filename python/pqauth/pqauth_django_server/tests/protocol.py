
"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from django.core.urlresolvers import reverse
from django.conf import settings

from pqauth import crypto
from pqauth.client import PQAuthClient
from pqauth.pqauth_django_server.views import hello
from pqauth.pqauth_django_server.views import confirm
from pqauth.pqauth_django_server.keys import SERVER_KEY
from pqauth.pqauth_django_server.models import PQAuthSession

CLIENT_KEY = crypto.load_key_file(settings.TEST_CLIENT_KEY)

def get_pqa_client():
    return PQAuthClient(CLIENT_KEY, SERVER_KEY)


class ProtocolTest(TestCase):
    fixtures = ["test_accounts.json"]

    def test_sunshine_and_unicorns(self):
        pqa_client = get_pqa_client()
        client_hello = pqa_client.encrypt_for_server(pqa_client.get_hello_message())

        hello_resp = self.client.generic("POST", reverse(hello), data=client_hello)
        self.assertEquals(200, hello_resp.status_code)

        decrypted_hello_resp = pqa_client.decrypt_from_server(hello_resp.content)
        pqa_client.process_hello_response(decrypted_hello_resp)

        self.assertEquals(pqa_client.client_guid, decrypted_hello_resp["client_guid"])
        self.assertIsNone(decrypted_hello_resp["expires"])

        confirm_msg = pqa_client.encrypt_for_server(pqa_client.get_confirmation_message())
        confirm_resp = self.client.generic("POST", reverse(confirm), data=confirm_msg)
        self.assertEquals(200, confirm_resp.status_code)

        session = PQAuthSession.objects.get(session_key=pqa_client.session_key)
        self.assertIsNotNone(PQAuthSession)
