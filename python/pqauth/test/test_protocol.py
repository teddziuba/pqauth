import time
import unittest
import collections

from pqauth import crypto
from pqauth.protocol import client
from pqauth.protocol import server
from pqauth.protocol import messages
from pqauth.protocol import ProtocolError
from pqauth.protocol import UnknownClient

Identity = collections.namedtuple("Identity", "public_key, fingerprint")

CLIENT_KEY = crypto.load_key_file("./keys/id_client")
CLIENT_ID = Identity(CLIENT_KEY, crypto.public_key_fingerprint(CLIENT_KEY))

SERVER_KEY = crypto.load_key_file("./keys/id_server")
SERVER_ID = Identity(SERVER_KEY, crypto.public_key_fingerprint(SERVER_KEY))

EVIL_KEY = crypto.load_key_file("./keys/id_evil")
EVIL_ID = Identity(EVIL_KEY, crypto.public_key_fingerprint(EVIL_KEY))

ID_MAP = {CLIENT_ID.fingerprint: CLIENT_ID,
          SERVER_ID.fingerprint: SERVER_ID}


CLIENT_HELLO_HANDLER = client.HelloHandler(CLIENT_KEY, ID_MAP)
CLIENT_HELLO_RESPONSE_HANDLER = client.HelloResponseHandler(CLIENT_KEY, ID_MAP)
CLIENT_CONFIRM_HANDLER = client.ConfirmationHandler(CLIENT_KEY, ID_MAP)

SERVER_HELLO_HANDLER = server.ClientHelloHandler(SERVER_KEY, ID_MAP)
SERVER_CONFIRM_HANDLER = server.ClientConfirmationHandler(SERVER_KEY, ID_MAP)

EVIL_SERVER_HELLO_HANDLER = server.ClientHelloHandler(EVIL_KEY, ID_MAP)
EVIL_CLIENT_HELLO_HANDLER = client.HelloHandler(EVIL_KEY, ID_MAP)

class ProtocolTest(unittest.TestCase):

    def test_happy_case(self):
        # Client HELLO's to the server
        hello_msg = CLIENT_HELLO_HANDLER.handle_step()
        client_guid = hello_msg["client_guid"]
        hello_encrypted = CLIENT_HELLO_HANDLER.encrypt(hello_msg, SERVER_ID)

        # Server looks up client's public key and formulates its
        hello_decrypted = SERVER_HELLO_HANDLER.decrypt(hello_encrypted)
        client_id, hello_response = SERVER_HELLO_HANDLER.handle_step(hello_decrypted)
        server_guid = hello_response["server_guid"]
        response_encrypted = SERVER_HELLO_HANDLER.encrypt(hello_response, CLIENT_ID)
        self.assertEquals(client_guid, hello_response["client_guid"])
        self.assertIsNone(hello_response["expires"])
        self.assertEquals(SERVER_ID.fingerprint, hello_response["server_key_fingerprint"])


        # Client verifies the server's reply
        response_plain = CLIENT_HELLO_RESPONSE_HANDLER.decrypt(response_encrypted)
        response_plain = CLIENT_HELLO_RESPONSE_HANDLER.handle_step(
            response_plain, SERVER_ID, client_guid)
        received_server_guid = response_plain["server_guid"]
        self.assertEquals(client_guid, response_plain["client_guid"])
        self.assertIsNone(hello_response["expires"])
        self.assertEquals(SERVER_ID.fingerprint, hello_response["server_key_fingerprint"])
        self.assertEquals(server_guid, received_server_guid)


        # Client generates confirmation message
        confirm_message = CLIENT_CONFIRM_HANDLER.handle_step(received_server_guid)
        confirm_encrypted = CLIENT_CONFIRM_HANDLER.encrypt(confirm_message, SERVER_ID)
        self.assertEquals(server_guid, confirm_message["server_guid"])


        # Server validates the client's confirmation
        confirm_decrypted = SERVER_CONFIRM_HANDLER.decrypt(confirm_encrypted)
        self.assertEquals(server_guid, confirm_decrypted["server_guid"])


    def test_client_discovers_man_in_the_middle_attack(self):
        """
        This tests the "Lowe" part of the Needham-Schroeder-Lowe
        protocol.

        Lowe's paper on the MitM vulnerability in Needham-Schroeder:
        http://web.comlab.ox.ac.uk/oucl/work/gavin.lowe/Security/Papers/NSPKP.ps

        The solution is for the server to provide its own identity
        in the hello response, which it does in pqAuth by including
        the fingerprint of its own public key.
        """

        # Client believes it's communicating with the legit server,
        # but it's actually communicating with the evil server.
        client_hello = CLIENT_HELLO_HANDLER.handle_step()
        client_guid = client_hello["client_guid"]
        hello_encrypted = CLIENT_HELLO_HANDLER.encrypt(client_hello, EVIL_ID)

        # Evildoer intercepts and decrypts client message
        decrypted_hello = EVIL_SERVER_HELLO_HANDLER.decrypt(hello_encrypted)


        # Evildoer sends client's HELLO to the legit server
        evil_hello = EVIL_CLIENT_HELLO_HANDLER.encrypt(decrypted_hello, SERVER_ID)


        # Legit server responds, encrypting with client's key. Server believes
        # it is communicating with client, but it's actually communicating
        # with the evildoer.
        decrypted_evil_hello = SERVER_HELLO_HANDLER.decrypt(evil_hello)
        client_id, legit_hello_response = SERVER_HELLO_HANDLER.handle_step(
            decrypted_evil_hello)
        encrypted_legit_response = SERVER_HELLO_HANDLER.encrypt(legit_hello_response,
                                                                client_id)


        # The evil server then proxies this legit_response back to the client,
        # who gets wise, since the fingerprint in the response doesn't match
        # the fingerprint it has for the server.
        # (It's been encrypting with EVIL_KEY)
        decrypted_legit_response = CLIENT_HELLO_RESPONSE_HANDLER.decrypt(
            encrypted_legit_response)
        self.assertRaises(ProtocolError, CLIENT_HELLO_RESPONSE_HANDLER.handle_step,
                          decrypted_legit_response, EVIL_ID, client_guid)


    def test_client_receives_expiry_timestamp(self):
        client_hello = CLIENT_HELLO_HANDLER.handle_step()
        client_guid = client_hello["client_guid"]
        hello_encrypted = CLIENT_HELLO_HANDLER.encrypt(client_hello, SERVER_ID)

        sent_expires = int(time.time())

        decrypted_hello = SERVER_HELLO_HANDLER.decrypt(hello_encrypted)
        client_id, hello_response = SERVER_HELLO_HANDLER.handle_step(decrypted_hello,
                                                                     sent_expires)
        response_encrypted = SERVER_HELLO_HANDLER.encrypt(hello_response, client_id)


        hello_decrypted = CLIENT_HELLO_RESPONSE_HANDLER.decrypt(response_encrypted)
        received_hello_response = CLIENT_HELLO_RESPONSE_HANDLER.handle_step(
            hello_decrypted, SERVER_ID, client_guid)

        self.assertEquals(sent_expires, received_hello_response["expires"])


if __name__ == "__main__":
    unittest.main()
