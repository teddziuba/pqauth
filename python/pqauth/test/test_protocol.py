import unittest

from pqauth import crypto
from pqauth.protocol import client
from pqauth.protocol import server
from pqauth.protocol import messages
from pqauth.protocol import ProtocolError
from pqauth.protocol import UnknownClient


CLIENT_KEY = crypto.load_key_file("./keys/id_client")
SERVER_KEY = crypto.load_key_file("./keys/id_server")
EVIL_KEY = crypto.load_key_file("./keys/id_evil")

KEY_STORE = server.MemoryClientPublicKeyStore([CLIENT_KEY])


class ProtocolTest(unittest.TestCase):

    def test_happy_case(self):
        # Client HELLO's to the server
        client_guid, client_hello = client.get_hello_message(CLIENT_KEY,
                                                             SERVER_KEY)

        # Server looks up client's public key and formulates its reply.
        server_guid, hello_response = server.get_client_hello_response(
            client_hello, SERVER_KEY, KEY_STORE, None)

        # Client verifies the server's reply
        returned_server_guid, expires = client.validate_server_hello_response(
            hello_response, client_guid, CLIENT_KEY, SERVER_KEY)

        self.assertEquals(server_guid, returned_server_guid)
        self.assertIsNone(expires)

        # Client generates confirmation message
        confirm_message = client.get_confirmation_message(returned_server_guid,
                                                          SERVER_KEY)

        # Server validates the client's confirmation
        auth_success = server.validate_client_confirmation_message(
            confirm_message, SERVER_KEY, server_guid)

        self.assertTrue(auth_success)


    def test_unknown_client(self):
        # Unknown client/evildoer generates a HELLO message
        _, client_hello = client.get_hello_message(EVIL_KEY, SERVER_KEY)

        # Server raises an error since it can't ID the client
        self.assertRaises(UnknownClient, server.get_client_hello_response,
                          client_hello, SERVER_KEY, KEY_STORE, None)


    def test_client_has_wrong_server_key(self):

        # Client encrypts with the evildoer's public key
        _, client_hello = client.get_hello_message(CLIENT_KEY, EVIL_KEY)

        # Server tries to decrypt message with the right key, fails
        self.assertRaises(ProtocolError, server.get_client_hello_response,
                          client_hello, SERVER_KEY, KEY_STORE, None)


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
        client_guid, client_hello = client.get_hello_message(CLIENT_KEY, EVIL_KEY)

        # Evildoer intercepts and decrypts client message
        decrypted_hello = messages.decrypt(client_hello, EVIL_KEY)

        # Evildoer sends client's HELLO to the legit server
        re_encrypted_hello = messages.encrypt(decrypted_hello, SERVER_KEY)

        # Legit server responds, encrypting with client's key. Server believes
        # it is communicating with client, but it's actually communicating
        # with the evildoer.
        legit_response = server.get_client_hello_response(re_encrypted_hello,
                                                          SERVER_KEY, KEY_STORE,
                                                          None)

        # The evil server then proxies this legit_response back to the client,
        # who gets wise, since the fingerprint in the response doesn't match
        # the fingerprint it has for the server.
        # (It's been encrypting with EVIL_KEY)
        self.assertRaises(ProtocolError, client.validate_server_hello_response,
                          legit_response, client_guid, CLIENT_KEY, EVIL_KEY)

if __name__ == "__main__":
    unittest.main()
