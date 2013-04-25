from pqauth.protocol import messages
from pqauth.protocol import ProtocolError
from pqauth import crypto



def get_hello_message(client_key, server_public_key):
    """
    Returns the text of the client's first message to the server,
    encrypted with the server's public key.

    This message contains the client's random GUID and the
    fingerprint of the client's public key.
    """

    whatup_message = messages.client_whatup_message(client_key)
    client_guid = whatup_message["client_guid"]
    encrypted = messages.encrypt(whatup_message, server_public_key)

    return client_guid, encrypted


def validate_server_hello_response(server_response, client_guid,
                                   client_key, server_public_key):
    """
    Returns (server_guid, expires) if the server's response
    is valid. Otherwise, raises ProtocolError.

    This function checks three conditions:

      1. The server's response is correctly encrypted
         with the client's public key.

      2. The server returned the same client_guid that the client
         sent in the initial hello message.

      3. The public key fingerprint the server sends for its own
         public key matches the fingerprint of the public key
         the client has for the server.


    If any of these conditions fail, this function raises ProtocolError.
    If all conditions succeed, the function returns the server GUID
    and the expiration timestamp (which is None if no expiration is set).
    """
    decrypted = messages.decrypt(server_response, client_key)
    returned_client_guid = decrypted["client_guid"]
    returned_server_fingerprint = decrypted["server_key_fingerprint"]


    if returned_client_guid != client_guid:
        msg = ("Server didn't send back the GUID we sent it. "
               "We sent: %s, it returned: %s" %
               (client_guid, returned_client_guid))
        raise ProtocolError(msg)

    expected_fingerprint = crypto.public_key_fingerprint(server_public_key)
    if returned_server_fingerprint != expected_fingerprint:
        msg = ("Server key fingerprint didn't match the server key we have. "
               "We have: %s, it returned: %s" %
               (expected_fingerprint, returned_server_fingerprint))
        raise ProtocolError(msg)

    return decrypted["server_guid"], decrypted["expires"]


def get_confirmation_message(server_guid, server_public_key):
    """
    Returns the client's final message to the server. This message
    only contains the server's GUID, and is encrypted with the server's
    public key.

    If the server returns HTTP status code 200 from this request,
    authentication has succeeded. Otherwise, it has failed. It is
    up to the server to provide failure details.
    """
    confirm_message = messages.client_word_message(server_guid)
    encrypted = messages.encrypt(confirm_message, server_public_key)

    return encrypted
