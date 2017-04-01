from __future__ import unicode_literals
from datetime import datetime
from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class admins(models.Model):
	user = models.OneToOneField(User, on_delete = models.CASCADE)
	dept = models.CharField(max_length = 10)
class Packet(models.Model):
	"""docstring for Packet
	def __init__(self, arg):
		super(Packet, self).__init__()
		self.arg = arg"""
	timestamp = models.DateTimeField(auto_now_add=True)	
	srcIP = models.CharField(max_length = 25)
	desIP = models.CharField(max_length = 25)
	breach_confidence = models.IntegerField()
	Com_MAC = models.CharField(max_length = 19,default="0.0.0.0")
class CT(models.Model):
	pac = models.ForeignKey(Packet, on_delete = models.CASCADE)
	catg = models.CharField(max_length = 25)
	geolat = models.FloatField()
	geolon = models.FloatField()
class traff(models.Model):
	timestamp = models.CharField(max_length = 25, default=datetime.now().strftime("%B"))
	traffic = models.IntegerField()