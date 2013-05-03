from django.contrib import admin

from django_pqauth_server.models import PublicKey
from django_pqauth_server.models import PQAuthSession

admin.site.register(PublicKey)
admin.site.register(PQAuthSession)
