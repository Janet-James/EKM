from django.contrib import admin
from backend.models import *

# Register your models here.

@admin.register(application,algorithm,keys)
class EKMAdmin(admin.ModelAdmin):
    pass