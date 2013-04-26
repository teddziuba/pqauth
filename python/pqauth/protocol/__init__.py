from pqauth.protocol import messages

class ProtocolError(Exception):
    pass


class UnknownClient(ProtocolError):
    pass


class ProtocolStepHandler(object):
    def __init__(self, my_key, identity_map=None):
        self.key = my_key

        if identity_map is None:
            self.identity_map = {}
        else:
            self.identity_map = identity_map

    def get_identity(self, id_fingerprint):
        return self.identity_map.get(id_fingerprint, None)

    def encrypt(self, message, recipient_identity):
        return messages.encrypt(message, recipient_identity.public_key)

    def decrypt(self, message):
        return messages.decrypt(message, self.key)
