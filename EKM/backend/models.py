from django.db import models
from django.contrib.auth.models import User

class application(models.Model):
    application_name = models.CharField(max_length=255, default='null')
    application_api_token = models.TextField(null=True, default='null')
    application_created_date = models.DateTimeField(blank=True)
    application_modified_date = models.DateTimeField(auto_now=True, blank=True)
    is_active = models.BooleanField(default='1')

class algorithm(models.Model):
    algorithm_name = models.CharField(max_length=255, default='null')
    algorithm_created_by_id = models.ForeignKey(User)
    algorithm_modified_by_id = models.IntegerField()
    algorithm_created_by_date = models.DateTimeField(blank=True)
    algorithm_modified_by_date = models.DateTimeField(auto_now=True, blank=True)
    is_active = models.BooleanField(default='1')

#### REMOVED ###
# class encryption(models.Model):
#     encryption_key_id = models.IntegerField()
#     encryption_app_id = models.ForeignKey(application)
#     encryption_data_type = models.CharField(max_length=255, default='null')
#     encryption_algorithm_id = models.ForeignKey(algorithm)
#     encryption_data_name = models.CharField(max_length=255, default='null')
#     encryption_created_date = models.DateTimeField(auto_now=True, blank=True)
#     is_active = models.BooleanField(default='1')
#### REMOVED ###

class keys(models.Model):
    key_secret = models.TextField(null=True,default='null')
    key_app_id = models.ForeignKey(application)
    key_public = models.TextField(null=True,default='null')
    key_private = models.TextField(null=True, default='null')
    key_created_date = models.DateTimeField(auto_now=True, blank=True)
    is_active = models.BooleanField(default='1')

class activities(models.Model):
    activities_app_id = models.IntegerField()
    activities_type = models.CharField(max_length=255, default='null')
    activities_data_name = models.CharField(max_length=255, default='null')
    activities_status = models.CharField(max_length=255, default='null')
    activities_created_date = models.DateTimeField(auto_now=True, blank=True)

class auth_key(models.Model):
    secret_code= models.TextField(null=True,default='null')
    login_user=models.ForeignKey(User)
    secret_code_modified_date = models.DateTimeField(auto_now=True, blank=True)