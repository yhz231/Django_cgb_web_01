from django.conf.urls import *
from baseline import views
import DjangoWeb.settings
# from .views import  UserInfoUpdate
from webserver.views import login
from django.contrib.auth import views as user_views

urlpatterns = [
    url(r'(?P<subject>[^/]+)/$', views.baseLineSubject, name='baselineSubject'),
    url(r'(?P<vendor>[^/]+)/(?P<type>[^/]+)', views.baseLine, name='baselineVendor'),
    url(r'$', views.baseLineIndex, name='baseLineIndex'),
]

