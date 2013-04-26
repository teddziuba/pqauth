from django.conf.urls import patterns, include, url

from django_pqauth_server import views

urlpatterns = patterns(
    "",
    url(r"^public-key", views.public_key),
    url(r"^hello", views.handle_client_hello),
    url(r"^confirm", views.handle_client_confirmation)
)
