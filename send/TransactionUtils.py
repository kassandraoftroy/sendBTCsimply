from blockchain import pushtx, blockexplorer
from bitcoin import *
import hashlib, ecdsa, binascii
from ecdsa import SigningKey, SECP256k1
from operator import itemgetter

def quick_unsigned_tx(from_, to_, satoshi_amount, satoshi_fee):
	outs = [{'value':satoshi_amount, 'address':to_}]
	return unsigned_tx(from_, outs, satoshi_fee)

def convert_single_input(input_):
	prev_tx_raw = input_['output'].split(":")
	prev_index_padded = "".join(["0" for i in range(8-len(hex(int(prev_tx_raw[1]))[2:]))])+hex(int(prev_tx_raw[1]))[2:]
	prev_index_endian = "".join(list(reversed([prev_index_padded[2*i:2*(i+1)] for i in range(len(prev_index_padded)/2)]))) 
	prev_tx_hash_r = "".join(list(reversed([prev_tx_raw[0][2*i:2*(i+1)] for i in range(len(prev_tx_raw[0])/2)])))
	collected_input_data = prev_tx_hash_r + prev_index_endian
	return collected_input_data

def convert_single_output(output_):
	output_value_padded = "".join(["0" for i in range(16-len(hex(output_['value'])[2:]))])+hex(output_['value'])[2:]
	output_value_endian = "".join(list(reversed([output_value_padded[2*i:2*(i+1)] for i in range(len(output_value_padded)/2)])))
	collected_output_data = output_value_endian+'1976a914'+b58check_to_hex(output_['address'])+'88ac'
	return collected_output_data

def choose_inputs(utxos, amount, protocol='basic'):
	tx_inputs = []
	try:
		if protocol == 'all':
			return utxos
		elif protocol == 'basic':
			utxos = sorted(utxos, key=itemgetter('value'), reverse=True)
		elif protocol == 'small_first':
			utxos = sorted(utxos, key=itemgetter('value'))
		i = 0
		input_tally = 0
		while input_tally < amount:
			tx_inputs.append(utxos[i])
			input_tally += utxos[i]['value']
			i += 1
		return tx_inputs
	except:
		return -1


def unsigned_tx(from_, outputs, satoshi_fee, inputs_protocol='basic'):
	gross_input_thresh = sum([i['value'] for i in outputs]) + satoshi_fee
	utxos = unspent(from_)
	tx_inputs = choose_inputs(utxos, gross_input_thresh, protocol=inputs_protocol)
	tx_outputs = outputs
	gross_input = sum([i['value'] for i in tx_inputs])
	if gross_input > gross_input_thresh:
		tx_outputs.append({'value':gross_input - gross_input_thresh, 'address':from_})
	elif gross_input == gross_input_thresh:
		pass
	else:
		print "Error. Abort Tx."
		return -1
	n_inputs = int2hexbyte(len(tx_inputs))
	n_outputs = int2hexbyte(len(tx_outputs))
	if n_inputs==-1 or n_outputs == -1:
		print "Error: Max inputs/outputs is 256. Abort Tx."
		return -1
	bytes_ = '01000000'+n_inputs+"".join([convert_single_input(i)+'00ffffffff' for i in tx_inputs])+n_outputs+"".join([convert_single_output(i) for i in tx_outputs])+'00000000'
	return bytes_

def sign_tx(hex_data, private_key):
	public_address = pubtoaddr(privtopub(private_key))
	pubkey = privtopub(private_key)
	split_data = hex_data.split("00ffffffff")
	input_stubs = split_data[:-1]
	output_stub = split_data[-1]
	pre_sig_script = '1976a914'+b58check_to_hex(public_address)+'88acffffffff'
	sig_stubs = []
	for i in range(len(input_stubs)):
		signing_message = ''
		for j in range(i):
			signing_message += input_stubs[j]+'00ffffffff'
		signing_message += input_stubs[i] + pre_sig_script
		for k in range(i+1, len(input_stubs)):
			signing_message += input_stubs[k]+'00ffffffff'
		signing_message += output_stub+'01000000'
		hashed_message = hashlib.sha256(hashlib.sha256(signing_message.decode('hex')).digest()).digest()
		signingkey = ecdsa.SigningKey.from_string(b58check_to_hex(private_key).decode('hex'), curve=ecdsa.SECP256k1)
		SIG = binascii.hexlify(signingkey.sign_digest(hashed_message, sigencode=ecdsa.util.sigencode_der_canonize))
		ScriptSig = hex(len(SIG+'01')/2)[2:] + SIG + '01' + hex(len(pubkey)/2)[2:] + pubkey	
		ScriptLength = hex(len(ScriptSig)/2)[2:]
		sig_stub = ScriptLength+ScriptSig+'ffffffff'
		sig_stubs.append(sig_stub)
	bytes_ = ''
	for q in range(len(sig_stubs)):
		bytes_ += input_stubs[q]+sig_stubs[q]
	bytes_ += output_stub
	return bytes_

def decode_tx(bytes_):
	readable = deserialize(bytes_)
	inputs_decoded = [{'address': blockexplorer.get_tx(i['outpoint']['hash']).outputs[i['outpoint']['index']].address, 'value' : blockexplorer.get_tx(i['outpoint']['hash']).outputs[i['outpoint']['index']].value, 'prev_hash':i['outpoint']['hash'], 'index':i['outpoint']['index'], 'script':i['script'], 'sequence':i['sequence']}for i in readable['ins']]
	outputs_decoded = [{'address' : hex_to_b58check(i['script'][6:-4]), 'value': i['value'], 'script':i['script']} for i in readable['outs']]
	all_addresses = list(set([i['address'] for i in inputs_decoded] + [j['address'] for j in outputs_decoded]))
	full_decode = {'addresses': all_addresses, 'version': readable['version'], 'size':len(bytes_)/2, 'fees': sum([i['value'] for i in inputs_decoded]) - sum([i['value'] for i in outputs_decoded]), 'locktime':readable['locktime'], 'inputs':inputs_decoded, 'outputs':outputs_decoded}
	return full_decode

def get_txid(bytes_):
	return sha256(sha256(bytes_.decode('hex')).digest()).digest()[::-1].encode('hex')

def get_utxos(addr):
	return unspent(addr)

def get_address(addr):
	address_info = blockexplorer.get_address(addr)
	return address_info

def txsize_est(from_, outputs):
	utxos = unspent(from_)
	gross_input_thresh = sum([i['value'] for i in outputs]) + 1000
	tx_inputs = choose_inputs(utxos, gross_input_thresh)
	bytes_est = 168*len(tx_inputs)+34*(len(outputs)+1) + 24
	return int(round(bytes_est/10.0)*10)

def broadcast_tx(data):
	pushtx(data)

def prepare_sig(hex_data, address):
	split_data = hex_data.split("00ffffffff")
	input_stubs = split_data[:-1]
	output_stub = split_data[-1]
	pre_sig_script = '1976a914'+b58decode(address)+'88acffffffff'
	hashes = []
	for i in range(len(input_stubs)):
		signing_message = ''
		for j in range(i):
			signing_message += input_stubs[j]+'00ffffffff'
		signing_message += input_stubs[i] + pre_sig_script
		for k in range(i+1, len(input_stubs)):
			signing_message += input_stubs[k]+'00ffffffff'
		signing_message += output_stub+'01000000'
		hashed_message = hashlib.sha256(hashlib.sha256(signing_message.decode('hex')).digest()).digest()
		hashes.append(hashed_message)
	return hashes

def apply_sig(hex_data, sigs):
	split_data = hex_data.split("00ffffffff")
	input_stubs = split_data[:-1]
	output_stub = split_data[-1]
	bytes_ = ''
	for q in range(len(sigs)):
		bytes_ += input_stubs[q]+sigs[q]
	bytes_ += output_stub
	return bytes_

def int2hexbyte(int_):
	raw_hex = hex(int_)[2:]
	if len(raw_hex) == 1:
		byte_ = '0'+raw_hex
	elif len(raw_hex) == 2:
		byte_ = raw_hex
	else:
		return -1
	return byte_

b58dict = {0:'1', 1:'2', 2:'3', 3:'4', 4:'5',5:'6',6:'7',7:'8',8:'9',9:'A',10:'B',11:'C',12:'D',13:'E',14:'F',15:'G',16:'H',17:'J',18:'K',19:'L',20:'M',21:'N',22:'P',23:'Q',24:'R',25:'S',26:'T',27:'U',28:'V',29:'W',30:'X',31:'Y',32:'Z',33:'a',34:'b',35:'c',36:'d',37:'e',38:'f',39:'g',40:'h',41:'i',42:'j',43:'k',44:'m',45:'n',46:'o',47:'p',48:'q',49:'r',50:'s',51:'t',52:'u',53:'v',54:'w',55:'x',56:'y',57:'z'}
b58inv = {v: k for k, v in b58dict.iteritems()}

def b58encode(hex_string):
	number = int(hex_string, 16)
	nums = []
	while number>0:
		nums.append(b58dict[number%58])
		number = number//58
	return ''.join(reversed(nums))

def b58decode(b58_string, btc=True):
	power = len(b58_string)-1
	num = 0
	for char in b58_string:
		num += b58inv[char]*(58**power)
		power -= 1
	out = hex(num)[2:]
	if out[-1]=='L':
		out = out[:-1]
	out = out[:-8] if btc else out
	out = out if b58_string[0]=='1' else out[2:]
	return out
