from pqauth.protocol import messages
from pqauth.protocol import ProtocolError
from pqauth.protocol import UnknownClient
from pqauth import crypto


class ClientPublicKeyStore(object):
    """
    Subclass this to look up full client public keys from
    their fingerprints.
    """

    def lookup_public_key(self, fingerprint):
        """
        Given the fingerprint as a string, return an instance
        of Crypto.PublicKey.RSA._RSAobj or None if the key
        cannot be found.
        """
        raise NotImplementedError


class MemoryClientPublicKeyStore(ClientPublicKeyStore):
    """
    An example ClientPublicKeyStore backed by a dictionary in-memory.

    This probably isn't suitable for production, since it's all in
    memory on a single machine.
    """

    def __init__(self, client_keys):
        self.key_store = {}
        for k in client_keys:
            self.add_key(k)


    def add_key(self, client_key):
        fingerprint = crypto.public_key_fingerprint(client_key)
        self.key_store[fingerprint] = client_key


    def lookup_public_key(self, fingerprint):
        return self.key_store.get(fingerprint, None)


def get_client_hello_response(hello_request, server_key,
                              client_key_store, expires=None):
    """
    Returns (server_guid, encrypted_response) if the client's hello
    request is valid, otherwise, raises ProtocolError.


    This function looks up the client's public RSA key from the
    client_key_fingerprint that the client sends using client_key_store.

    If that lookup fails (returns None), this function will raise
    UnknownClient.

    You can use server_guid to uniquely identify this authentication
    negotiation session.
    """
    decrypted = messages.decrypt(hello_request, server_key)

    client_guid = decrypted["client_guid"]
    client_key_fingerprint = decrypted["client_key_fingerprint"]

    client_key = client_key_store.lookup_public_key(client_key_fingerprint)
    if client_key is None:
        msg = "Unknown client key fingerprint: %s" % client_key_fingerprint
        raise UnknownClient(msg)

    response = messages.server_yaheard_message(client_guid, server_key, expires)
    server_guid = response["server_guid"]
    encrypted = messages.encrypt(response, client_key)


    return server_guid, encrypted


def validate_client_confirmation_message(confirmation_message,
                                         server_key, server_guid):
    """
    Verify that the client sent back the expected server GUID
    in its final message.

    If the client sent back the expected GUID, returns True.

    Otherwise, raises ProtocolError.

    If this function succeeds, authentication has succeeded. In that case,
    send back HTTP 200 to the client.
    """
    decrypted = messages.decrypt(confirmation_message, server_key)
    returned_server_guid = decrypted["server_guid"]

    if returned_server_guid != server_guid:
        msg = ("Client didn't send back the GUID we sent. "
               "We sent: %s, it returned: %s" %
               (server_guid, returned_server_guid))
        raise ProtocolError(msg)

    return True
