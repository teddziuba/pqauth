
"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from django.test.client import Client
from django.core.urlresolvers import reverse

from .views import hello

class ClientHelloTest(TestCase):
    def test_request_bad_decryption(self):
        client = Client()
        bad_post = client.generic("POST", reverse(hello), data="bad-data")
        self.assertEquals(400, bad_post.status_code)
