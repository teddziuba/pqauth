from pqauth.protocol import messages
from pqauth.protocol import UnknownClient
from pqauth.protocol import ProtocolStepHandler


class ClientHelloHandler(ProtocolStepHandler):

    def get_client_key_fingerprint(self, client_hello):
        return client_hello["client_key_fingerprint"]

    def validate_client_identity(self, client_identity):
        if client_identity is None:
            raise UnknownClient("Unknown client")

    def handle_step(self, hello, expires=None):
        client_fp = self.get_client_key_fingerprint(hello)
        client_identity = self.get_identity(client_fp)

        self.validate_client_identity(client_identity)

        response = messages.server_yaheard_message(hello["client_guid"],
                                                   self.key, expires)

        return client_identity, response

class ClientConfirmationHandler(ProtocolStepHandler):
    pass
