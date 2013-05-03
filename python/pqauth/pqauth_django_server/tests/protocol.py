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
EVIL_KEY = crypto.load_key_file(settings.TEST_EVIL_KEY)

def get_pqa_client():
    return PQAuthClient(CLIENT_KEY, SERVER_KEY)

def get_evil_pqa_client():
    return PQAuthClient(EVIL_KEY, SERVER_KEY)


class ProtocolTest(TestCase):
    fixtures = ["test_accounts.json"]

    def post_hello(self, pqa_client):
        plaintext_message = pqa_client.get_hello_message()
        client_hello = pqa_client.encrypt_for_server(plaintext_message)
        response = self.client.generic("POST", reverse(hello), data=client_hello)

        return response

    def test_sunshine_and_unicorns(self):
        pqa_client = get_pqa_client()
        hello_resp = self.post_hello(pqa_client)

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


    def test_unknown_client(self):
        # Unknown client
        # Server's all like "I have no memory of this place"

        evil_client = get_evil_pqa_client()
        hello_resp = self.post_hello(evil_client)

        self.assertEquals(403, hello_resp.status_code)


    def test_mystery_confirmation_guid(self):
        # Confirmation server_guid not in the DB
        pqa_client = get_pqa_client()
        unknown_confirmation = {"server_guid": crypto.random_guid()}
        encrypted = pqa_client.encrypt_for_server(unknown_confirmation)

        confirm_resp = self.client.generic("POST", reverse(confirm), data=encrypted)
        self.assertEquals(200, confirm_resp.status_code)

        n_sessions = PQAuthSession.objects.count()
        self.assertEquals(0, n_sessions)


    def test_bad_encryption(self):
        # Encrypted with a different pubkey
        # Client doesn't know where he is and is confused as hell

        stoned_client = PQAuthClient(CLIENT_KEY, EVIL_KEY)
        hello_resp = self.post_hello(stoned_client)

        self.assertEquals(400, hello_resp.status_code)
