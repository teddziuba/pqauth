import collections
import urllib2

from pqauth.protocol import messages
from pqauth.protocol import ProtocolError
from pqauth.protocol import ProtocolStepHandler
from pqauth import crypto


class HelloHandler(ProtocolStepHandler):

    def handle_step(self):
        message = messages.client_whatup_message(self.key)
        return message


class HelloResponseHandler(ProtocolStepHandler):

    def check_returned_client_guid(self, expected_guid, response):
        returned_guid = response["client_guid"]
        if returned_guid != expected_guid:
            msg = ("Server didn't send back the GUID we sent it. "
                   "We sent: %s, it returned: %s" %
                   (expected_guid, returned_guid))
            raise ProtocolError(msg)
        return True

    def check_returned_server_identity(self, expected_identity, response):
        returned_fingerprint = response["server_key_fingerprint"]
        if returned_fingerprint != expected_identity.fingerprint:
            msg = ("Server key fingerprint didn't match the server key we have. "
                   "We have: %s, it returned: %s" %
                   (expected_identity.fingerprint, returned_fingerprint))
            raise ProtocolError(msg)
        return True

    def handle_step(self, server_response, server_identity, client_guid):
        self.check_returned_client_guid(client_guid, server_response)
        self.check_returned_server_identity(server_identity, server_response)

        return server_response


class ConfirmationHandler(ProtocolStepHandler):

    def handle_step(self, server_guid):
        message = messages.client_word_message(server_guid)
        return message


# TODO: This is a little cumbersome because I haven't got the
# ProtocolStepHandler abstraction quite right, recognizing that
# server implementations will be far more diverse than client implementations.
class ClientAuthenticator(object):
    Identity = collections.namedtuple("Identity", "public_key, fingerprint")

    def __init__(self, client_key, server_key,
                 server_hello_url, server_confirm_url):
        self.key = client_key
        self.server_hello_url = server_hello_url
        self.server_confirm_url = server_confirm_url

        server_fp = crypto.public_key_fingerprint(server_key)
        self.server_id = ClientAuthenticator.Identity(server_key, server_fp)
        id_map = {self.server_id.fingerprint: self.server_id}

        self._hello_handler = HelloHandler(self.key, id_map)
        self._hello_response_handler = HelloResponseHandler(self.key, id_map)
        self._confirmation_handler = ConfirmationHandler(self.key, id_map)

    def post(self, url, body):
        try:
            response = urllib2.urlopen(url, data=body).read()
            return response
        except urllib2.HTTPError, e:
            e.msg = e.fp.read()
            raise e

    def hello(self):
        hello_msg = self._hello_handler.handle_step()
        client_guid = hello_msg["client_guid"]
        hello_post = self._hello_handler.encrypt(hello_msg, self.server_id)

        hello_response = self.post(self.server_hello_url, hello_post)

        return client_guid, hello_response

    def handle_hello_response(self, hello_response, client_guid):
        response = self._hello_response_handler.decrypt(hello_response)
        response = self._hello_response_handler.handle_step(response,
                                                            self.server_id,
                                                            client_guid)
        return response["server_guid"]

    def confirm(self, server_guid):
        message = self._confirmation_handler.handle_step(server_guid)
        encrypted = self._confirmation_handler.encrypt(message, self.server_id)

        self.post(self.server_confirm_url, encrypted)

    def authenticate(self):
        client_guid, hello_response = self.hello()
        server_guid = self.handle_hello_response(hello_response, client_guid)
        self.confirm(server_guid)

        session_key = messages.get_session_key(client_guid, server_guid)
        return session_key


def load_key_from_url(url):
    key_text = urllib2.urlopen(url).read()
    return crypto.rsa_key(key_text)


def main():
    client_key = crypto.load_key_file("test/keys/id_client")
    server_key = load_key_from_url("http://localhost:8000/pqauth/public-key")

    hello_url = "http://localhost:8000/pqauth/hello"
    confirm_url = "http://localhost:8000/pqauth/confirm"

    authenticator = ClientAuthenticator(client_key, server_key,
                                        hello_url, confirm_url)
    session_key = authenticator.authenticate()
    print "Authentication success, key = %s" % session_key

if __name__ == "__main__":
    main()

