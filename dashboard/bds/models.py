from __future__ import unicode_literals

from django.db import models

# Create your models here.

class Packet(models.Model):
	"""docstring for Packet"""
	def __init__(self, arg):
		super(Packet, self).__init__()
		self.arg = arg
	srcIP = models.CharField(max_length=16)
	desIP = models.CharField(max_length=16)
	breach_confidence = models.IntegerField()
	remark = models.CharField(max_length=250)