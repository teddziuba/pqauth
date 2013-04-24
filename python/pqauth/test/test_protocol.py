import unittest

from pqauth import crypto
from pqauth.client import PQAuthClient
from pqauth.server import PQAuthServerFlow

CLIENT_KEY = crypto.load_key_file("./keys/id_client")
SERVER_KEY = crypto.load_key_file("./keys/id_server")
BOGUS_SERVER_KEY = crypto.load_key_file("./keys/id_bogus_server")


class ProtocolTest(unittest.TestCase):

    def test_happy_case(self):
        client = PQAuthClient(CLIENT_KEY, SERVER_KEY)
        server = PQAuthServerFlow(SERVER_KEY)

        # jacked, for testing
        server._client_public_key = CLIENT_KEY


        init_msg = client.get_init_message()
        server.process_client_init_request(init_msg)

        init_response = server.get_client_init_response()
        client.process_server_init_response(init_response)

        final_msg = client.get_final_message()
        server.process_client_final_message(final_msg)

        self.assertTrue(server.session_key is not None)
        self.assertTrue(client.session_key is not None)
        self.assertEquals(server.session_key, client.session_key)


if __name__ == "__main__":
    unittest.main()
