import json

from pqauth import crypto


class ProtocolError(Exception):
    pass


class PQAuthClient(object):
    def __init__(self, client_key, server_key):
        self.client_key = client_key
        self.server_key = server_key

        self.server_key_fprint = crypto.public_key_fingerprint(self.server_key)
        self.client_key_fprint = crypto.public_key_fingerprint(self.client_key)

        self.client_guid = None
        self.server_guid = None
        self.expires = None


    @property
    def session_key(self):
        return "%s:%s" % (self.client_guid, self.server_guid)


    def get_hello_message(self):
        self.client_guid = crypto.random_guid()

        hello_message = {"client_guid": self.client_guid,
                         "client_key_fingerprint": self.client_key_fprint}

        return hello_message


    def process_hello_response(self, response):
        # Check the server send back the client_guid we sent.
        if response["client_guid"] != self.client_guid:
            message = ("Server did not send back the expected client_guid. "
                       "Expected: %s, Got: %s" %
                       (self.client_guid, response["client_guid"]))
            raise ProtocolError(message)

        # Check the server's stated fingerprint matches the one we know
        if response["server_key_fingerprint"] != self.server_key_fprint:
            message = ("Server did not send back the expected key fingerprint. "
                       "Expected: %s, Got: %s" %
                       (self.server_key_fprint,
                        response["server_key_fingerprint"]))
            raise ProtocolError(message)

        self.expires = response["expires"]
        self.server_guid = response["server_guid"]


    def get_confirmation_message(self):
        confirm_message = {"server_guid": self.server_guid}
        return confirm_message


    def encrypt_for_server(self, message):
        as_json = json.dumps(message)
        return crypto.rsa_encrypt(as_json, self.server_key)


    def decrypt_from_server(self, encrypted):
        decrypted = crypto.rsa_decrypt(encrypted, self.client_key)
        return json.loads(decrypted)

