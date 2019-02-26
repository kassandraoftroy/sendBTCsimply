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
		s_address = str(request.POST.get("sender", None))
		receivers = request.POST.getlist("receivers[]", None)
		amounts = request.POST.getlist("amounts[]", None)
		fee = int(request.POST.get("fee", None))
		if s_address[0] not in ['m','n', '2', '1']:
			raise ValueError
		for i in range(len(receivers)):
			if receivers[i][0] not in ['m','n', '2', '1']:
				raise ValueError
	except:
		pass
	try:
		outs = [{'address':receivers[i], 'value':int(amounts[i])} for i in range(len(receivers))]
		bytes_ = unsigned_tx(s_address, outs, fee, testnet=s_address[0]!='1')
		hashes = [i.encode("hex") for i in prepare_sig(bytes_, s_address)]
	except:
		bytes_ = "Transaction Generation Failed:\nVerify all input fields.\nMake sure sender has enough funds for transaction and fee."
		hashes = []

	data = {'bytes_':bytes_, 'hashes':hashes}
	return JsonResponse(data)

def ajax_broadcast(request):

	bytes_ = str(request.POST.get("signed", None))
	
	try:
		broadcast_tx(bytes_)
		output = "Transaction Submitted."
		receipt = Broadcast()
		receipt.time = timezone.now()
		receipt.tx = bytes_
		receipt.save()
		txid = get_txid(bytes_)
	except Exception as x:
		output = str(repr(x))
		txid = '-'
	data = {'output':output, 'txid':txid}
	return JsonResponse(data)

def ajax_verify(request):

	bytes_ = str(request.POST.get('bytes_', None))

	try:
		data = decode_tx(bytes_)
	except:
		data = {'error': 'Cannot decode transaction!'}
	return JsonResponse(data)

def ajax_suggest(request):
	try:
		addr = str(request.POST.get('addr', None))
		nums = request.POST.getlist('amounts[]', None)
		o = [{'address': "none", 'value':int(num)} for num in nums]
		data = {"msg":txsize_est(addr, o)}
	except:
		data = {"msg": 0}
	return JsonResponse(data)


