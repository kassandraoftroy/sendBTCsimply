# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

class Broadcast(models.Model):
	time = models.DateTimeField('pubtime')
	tx = models.CharField(max_length=500)

	def __str__(self):
		return self.time
