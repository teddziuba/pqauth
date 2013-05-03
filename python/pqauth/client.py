import json

from pqauth import crypto


class PQAuthClient(object):
    def __init__(self, client_key, server_key):
        self.client_key = client_key
        self.server_key = server_key

        self.server_key_fprint = crypto.public_key_fingerprint(self.server_key)
        self.client_key_fprint = crypto.public_key_fingerprint(self.client_key)

        self.client_guid = None
        self.server_guid = None


    @property
    def session_key(self):
        return "%s:%s" % (self.client_guid, self.server_guid)


    def get_hello_message(self):
        self.client_guid = crypto.random_guid()

        hello_message = {"client_guid": self.client_guid,
                         "client_key_fingerprint": self.client_key_fprint}

        return hello_message


    def process_hello_response(self, response):
        if response["client_guid"] != self.client_guid:
            raise Exception("oh shit")
        # Check fprint
        # save expiry
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

