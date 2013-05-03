from pqauth.protocol.server import ClientPublicKeyStore
from pqauth import crypto

from django_pqauth_server.models import PublicKey


class DatabasePublicKeyStore(ClientPublicKeyStore):
    def lookup_public_key(self, fingerprint):
        try:
            key = PublicKey.objects.get(pk=fingerprint)
            return crypto.rsa_key(key.ssh_key)
        except PublicKey.DoesNotExist:
            pass

        return None

db_key_store = DatabasePublicKeyStore()
