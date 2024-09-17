from fabric.api import env
from fabric.operations import run, put, get
from django.conf import settings

env.host_string = '10.0.1.4'
env.user = 'nextaps'
env.password = 'Green%N$$xt'
env.port = 22

def Syncfiles():
  put(settings.MEDIA_ROOT,'/home/nextaps/MainStorage/',use_sudo=True)

def Getfile(file):
  get('/home/nextaps/MainStorage/media/'+file+'.enc','/home/nextaps/EncryptedStorage/media/',use_sudo=True)