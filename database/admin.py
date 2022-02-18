from django.contrib import admin
from .models import *

# # Register your models here.
admin.site.register(Administor)
admin.site.register(User)
admin.site.register(Request)
admin.site.register(Response)