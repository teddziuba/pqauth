from pqauth import protocol


class PQAuthServerFlow(object):
    def __init__(self, server_private_key):
        self.server_key = server_private_key

        self._client_public_key = None
        self._client_guid = None
        self._server_guid = None

    def lookup_client_public_key(self, fingerprint):
        raise NotImplementedError

    def process_client_init_request(self, request):
        decrypted = protocol.decrypt_message(request, self.server_key)
        self._client_guid = decrypted["client_guid"]

        fingerprint = decrypted["client_key_fingerprint"]
        if not self._client_public_key:
            lookup = self.lookup_client_public_key(fingerprint)
            if not lookup:
                raise protocol.ProtocolError("Unknown client fingerprint")
            self._client_public_key = lookup


    def get_client_init_response(self):
        yaheard = protocol.server_yaheard_message(self._client_guid, self.server_key)
        self._server_guid = yaheard["server_guid"]

        encrypted = protocol.encrypt_message(yaheard, self._client_public_key)
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
