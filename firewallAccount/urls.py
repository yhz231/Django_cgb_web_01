from django.conf.urls import *
from firewallAccount import views

urlpatterns = [
    url(r'fileupload/$', views.upload, name='fwFileUpload'),
    url(r'display/$', views.display, name='fwDisplay'),
]
