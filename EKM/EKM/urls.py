"""EKM URL Configuration

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
from django.conf.urls import url, include
from django.contrib import admin
from django.views.generic import RedirectView
from django.http import HttpResponse
from django.utils.translation import ugettext_lazy as _

urlpatterns = [
    url(r'^ekmadmin/', admin.site.urls),
    url(r'^api/v1/',include('backend.urls')),
    url(r'^api/', RedirectView.as_view(url='/api/v1/')),
    url(r'^', lambda req:HttpResponse("<h1>404 Invalid URL</h1>")),
    url(r'^.*/$', lambda req:HttpResponse("<h1>404 Invalid URL</h1>")),
]

admin.site.site_header = _("EKM Administration")
admin.site.site_title = _("Enterprise Key Management")