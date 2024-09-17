from django.conf.urls import url
from rest_framework_swagger.views import get_swagger_view
from .views import *

schema_view = get_swagger_view(title='EKM API')

urlpatterns = [
    url(r'^$', Invalid, name='404_invalid'),
    url(r'^client/$', schema_view, name='swagger'),
    url(r'^asymencrypt/$', AsymEncrypt, name='asymencrypt'),
    url(r'^asymdecrypt/$', AsymDecrypt, name='asymencrypt'),
    url(r'^symencrypt/$', SymEncrypt, name='symencrypt'),
    url(r'^symdecrypt/(?P<token>\w+)/(?P<file>[\w.\-]{0,256})$', SymDecrypt, name='symdecrypt'),
    url(r'^syncapp/$', syncapp, name='syncapp'),
    url(r'^applications/$', getApp, name='applications'),
    url(r'^keys/(?P<app_id>\d+)/$', getKey, name='keys'),
    url(r'^keys/$', getKeys, name='keys'),
    url(r'^login/$', login_auth, name='login'),
    url(r'^newsfeed/$', getNewsfeed, name='newsfeed'),
    url(r'^getencrypt/$', getEncryptions, name='getencrypt'),
    url(r'^getdecrypt/$', getDecryptions, name='getdecrypt'),
    url(r'^getencryptcount/(?P<app_id>\d+)/$', getEncryptionsCount, name='getencryptcount'),
    url(r'^getdecryptcount/(?P<app_id>\d+)/$', getDecryptionsCount, name='getdecryptcount'),
    url(r'^getserver/$', getServerStatus, name='getserver'),
    url(r'^twofactor/$', verifysecret, name='twofactor'),
    url(r'^footer/$', footerinfo, name='footer'),
    url(r'^updateapp/$', ApplicationStatus, name='updateapp'),
]