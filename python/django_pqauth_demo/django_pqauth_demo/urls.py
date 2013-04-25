from django.conf.urls import patterns, include, url
from django_pqauth_demo import views

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'django_pqauth_demo.views.home', name='home'),
    # url(r'^django_pqauth_demo/', include('django_pqauth_demo.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/endpoint$', views.access_controlled_endpoint)
)
