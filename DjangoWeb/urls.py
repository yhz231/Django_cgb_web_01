"""DjangoWeb URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.conf.urls import *
from webserver import views
import DjangoWeb.settings
# from .views import  UserInfoUpdate
from webserver.views import login
from django.contrib.auth import views as user_views
import django

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    #url(r'^login/$',views.login),
    #url(r'^index/$',views.index),
    #url(r'^logout/$',views.logout),
    #url(r'^user/list/$',views.userList, name='user_list'),
    #url(r'^user/list/(.+)/$',views.userList,name='user_listcc'),
    #url(r'^user/$',views.userList),
    #url(r'^user/add/$',views.userAdd),
    #url(r'^user/alter/(.+)/$',views.userAlter,name='user_alter'),
    # url(r'^user/alter/(?P<id>\d+)/$', UserInfoUpdate.userAlter,name='user_alter'),
    # url(r'^user/alter/(.+)/$', UserInfoUpdate.userAlter,name='user_alter'),
    #url(r'^cmdb/serverlist/$',views.serverList, name='server_list'),
    #url(r'^cmdb/serverlist/(.+)/$',views.serverList,name='server_listcc'),
    #url(r'^cmdb/serveradd/$',views.serverAdd, name='server_add'),
    #url(r'^cmdb/hostadmin/$',views.hostAdmin, name='hostadmin'),
    #url(r'^cmdb/monitor/$',views.getMonitor, name='monitor'),
    url(r'^cmdb/baseline/', include('baseline.urls', namespace='baseline_font')),
    url(r'^firewall/fwaccount/', include('firewallAccount.urls', namespace='fwaccount')),
    url(r'', include('webserver.urls', namespace='webserver')),
    #url(r'^cmdb/$',views.serverList),

]
