import json

from pqauth.crypto import public_key_fingerprint
from pqauth.crypto import rsa_encrypt
from pqauth.crypto import rsa_decrypt
from pqauth.crypto import random_guid
from pqauth.protocol import ProtocolError



def client_whatup_message(client_public_key):
    """
    Authentication Step 1

    Client sends a nonce to the server, along with a key fingerprint
    that identifies the client. The server has prior knowledge of the client's
    public key, and can look up the entire key given the fingerprint.


    Client: "What up, server?"
    """

    message = {"client_key_fingerprint": public_key_fingerprint(client_public_key),
               "client_guid": random_guid()}
    return message


def server_yaheard_message(client_guid, server_public_key, expires=None):
    """
    Authentication Step 2


    Server sends its own nonce back to the client, along with the nonce
    the client sends. Server also sends its own identity fingerprint.
    Optionally, the server may send an "expires" timestamp, after which
    the session key will no longer be honored.

    While not necessarily used for a key lookup on the client side, this
    mitigates a Man-In-The-Middle attack on the protocol, provided the
    client checks that the server's fingerprint matches the key the client
    is using to encrypt messages for the server.


    Server: "Yo dogg. Here's my nonce, ya heard?"
    """

    message = {"client_guid": client_guid,
               "server_guid": random_guid(),
               "expires": expires,
               "server_key_fingerprint": public_key_fingerprint(server_public_key)}
    return message


def client_word_message(server_guid):
    """
    Authentication Step 3

    Client returns the server's nonce back to it.

    Client: "Yeah I got your nonce. Word."
    """

    message = {"server_guid": server_guid}
    return message


def get_session_key(client_guid, server_guid):
    """
    Authentication Finished

    After the three steps, each party can independently construct the
    ephemeral session key. This is a shared secret that the client includes
    on subsequent API calls to identify itself.
    """

    return ":".join([client_guid, server_guid])


def encrypt(message, public_key):
    as_json = json.dumps(message)
    return rsa_encrypt(as_json, public_key)


def decrypt(message, private_key):
    try:
        json_string = rsa_decrypt(message, private_key)
    except ValueError, v:
        raise ProtocolError(v)

    return json.loads(json_string)


