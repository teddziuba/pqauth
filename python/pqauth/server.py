from pqauth import protocol


class PQAuthServer(object):
    def __init__(self, server_private_key, client_public_key):
        self.server_key = server_private_key
        self.client_public_key = client_public_key

        self._client_guid = None
        self._server_guid = None

    def process_client_init_request(self, request):
        decrypted = protocol.decrypt_message(request, self.server_key)
        self._client_guid = decrypted["client_guid"]

    def get_client_init_response(self):
        yaheard = protocol.server_yaheard_message(self._client_guid, self.server_key)
        self._server_guid = yaheard["server_guid"]

        encrypted = protocol.encrypt_message(yaheard, self.client_public_key)
        return encrypted

    def process_client_final_message(self, message):
        decrypted = protocol.decrypt_message(message, self.server_key)

        if decrypted["server_guid"] != self._server_guid:
            msg = ("Client didn't send back the GUID we sent. "
                   "We sent: %s, it returned: %s" %
                   (self._server_guid, decrypted["server_guid"]))
            raise protocol.ProtocolError(msg)

    @property
    def session_key(self):
        return protocol.get_session_key(self._client_guid, self._server_guid)
