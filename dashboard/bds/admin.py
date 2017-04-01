from django.contrib import admin
from bds.models import Packet
from bds.models import CT,admins

# Register your models here.
admin.site.register(Packet)
admin.site.register(CT)
admin.site.register(admins)
