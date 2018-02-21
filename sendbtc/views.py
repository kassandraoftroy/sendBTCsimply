# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from models import Broadcast
from TransactionUtils import *

def home(request):
	return render(request, "send.html")

def ajax_tx(request):
	try:
		s_address = str(request.GET.get("sender", None))
		r_address = str(request.GET.get("receiver", None))
		amount = int(request.GET.get("amount", None))
		fee = int(request.GET.get("fee", None))
	except:
		data = {'bytes_':'Transaction Generation Failed:\nVerify all input fields.'}
		return JsonResponse(data)
	try:
		bytes_ = quick_unsigned_tx(s_address, r_address, amount, fee)
	except:
		bytes_ = "Transaction Generation Failed:\nVerify all input fields.\nMake sure sender has enough funds for transaction and fee."
	data = {'bytes_':bytes_}
	return JsonResponse(data)

def ajax_broadcast(request):
	try:
		bytes_ = str(request.GET.get("signed", None))
	except:
		output = 'Error reading transaction (before broadcasting). Verify all input fields and try again.'
		data = {'output': output}
		return JsonResponse(data)
	
	try:
		broadcast_tx(bytes_)
		output = "Transaction Submitted."
		receipt = Broadcast()
		receipt.time = timezone.now()
		receipt.tx = bytes_
		receipt.save()
	except Exception as x:
		output = str(repr(x))
	data = {'output':output}
	return JsonResponse(data)

def tutorial_1(request):
	return render(request, "tutorial1.html")
