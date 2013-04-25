from django.contrib.auth.models import User
from django.db import models


class PublicKey(models.Model):
    user = models.ForeignKey(User, related_name="public_keys")

    # keys MD5-fingerprint to 47 characters, including colons for readability
    fingerprint = models.CharField(max_length=64, primary_key=True)
    ssh_key = models.TextField()


class PQAuthSession(models.Model):
    server_guid = models.CharField(max_length=32, primary_key=True)
    client_guid = models.CharField(max_length=32)
    session_key = models.CharField(max_length=65, unique=True,
                                   null=True, blank=True)
    expires = models.DateTimeField(null=True, blank=True)

    user = models.ForeignKey(User, related_name="pqauth_sessions")
