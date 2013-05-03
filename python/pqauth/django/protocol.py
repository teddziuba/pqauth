from pqauth.crypto import random_guid


def hello_response_message(client_guid, server_key_fingerprint, expires=None):
    message = {"client_guid": client_guid,
               "server_guid": random_guid(),
               "expires": expires,
               "server_key_fingerprint": server_key_fingerprint}

    return message


def get_session_key(client_guid, server_guid):
    return ":".join([client_guid, server_guid])
