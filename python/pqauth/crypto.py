from binascii import hexlify
import uuid

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
from paramiko.rsakey import RSAKey as ParamikoRSAKey


def load_key_file(path, passphrase=None):
    f = open(path, "rb")
    try:
        return rsa_key(f.read(), passphrase)
    finally:
        f.close()


def rsa_key(text, passphrase=None):
    return RSA.importKey(text, passphrase)


def public_key_fingerprint(key):
    # paramiko can compute the OpenSSH-style fingerprint
    # Only fingerprints the public key

    paramiko_key = ParamikoRSAKey(vals=(key.e, key.n))
    fp =  hexlify(paramiko_key.get_fingerprint())

    # OpenSSH puts a ":" character between every pair of hex-digits.
    # For whatever reason. Readability, I guess.
    openssh_fp = ":".join([a+b for a, b in zip(fp[::2], fp[1::2])])

    return openssh_fp


def rsa_encrypt(plaintext, receiver_public_key):
    cipher = PKCS1_OAEP.new(receiver_public_key)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext, receiver_private_key):
    cipher = PKCS1_OAEP.new(receiver_private_key)
    return cipher.decrypt(ciphertext)


def random_guid():
    secure_random = random.getrandbits(128)
    random_uuid = uuid.UUID(int=secure_random)
    return str(random_uuid)
