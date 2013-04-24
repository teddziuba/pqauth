from pqauth import protocol
from pqauth import crypto


class PQAuthClient(object):
    def __init__(self, client_private_key, server_public_key):
        self.client_key = client_private_key
        self.server_public_key = server_public_key

        self._server_fingerprint = crypto.public_key_fingerprint(
            self.server_public_key)
        self._client_guid = None
        self._server_guid = None


    def get_init_message(self):
        whatup_message = protocol.client_whatup_message(self.client_key)
        self._client_guid = whatup_message["client_guid"]

        encrypted = protocol.encrypt_message(whatup_message,
                                             self.server_public_key)
        return encrypted


    def process_server_init_response(self, server_response):
        decrypted = protocol.decrypt_message(server_response, self.client_key)

        if decrypted["client_guid"] != self._client_guid:
            msg = ("Server didn't send back the GUID we sent it. "
                   "We sent: %s, it returned: %s" %
                   (self._client_guid, decrypted["client_guid"]))
            raise protocol.ProtocolError(msg)


        if decrypted["server_key_fingerprint"] != self._server_fingerprint:
            msg = ("Server key fingerprint didn't match the server key we have. "
                   "We have: %s, it returned: %s" %
                   (self._server_fingerprint, decrypted["server_key_fingerprint"]))
            raise protocol.ProtocolError(msg)

        self._server_guid = decrypted["server_guid"]
        return True


    def get_final_message(self):
        word_message = protocol.client_word_message(self._server_guid)
        encrypted = protocol.encrypt_message(word_message,
                                             self.server_public_key)
        return encrypted


    @property
    def session_key(self):
        return protocol.get_session_key(self._client_guid, self._server_guid)
