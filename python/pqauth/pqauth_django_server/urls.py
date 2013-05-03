from django.conf.urls import patterns, url

from pqauth.pqauth_django_server import views

urlpatterns = patterns(
    "",
    url(r"^public-key", views.public_key),
    url(r"^hello", views.hello),
    url(r"^confirm", views.confirm)
)
