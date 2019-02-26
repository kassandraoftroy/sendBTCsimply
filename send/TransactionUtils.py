from blockchain import pushtx, blockexplorer
from bitcoin import *
import hashlib, ecdsa, binascii, requests
from ecdsa import *
from operator import itemgetter

G = ecdsa.generator_secp256k1
N = G.order()

def genECkeypair(priv=None, gen=G):
	if priv == None:
		gate = True
		while gate:
			priv = randrange(1,N)
			pub = priv*gen
			try:
				convertPub2Addr(convertPt2Pub(pub))
				gate = False
			except:
				pass
	else:
		pub = priv*gen
		convertPub2Addr(convertPt2Pub(pub))
	return priv, pub

def ECsign(h, priv):
	k = randrange(1, N)
	p1 = k*G 
	r = p1.x()%N
	s = mod_inv(k,N)*(h+r*priv)%N
	if s > N/2:
		s = N - s
	return r,s

def ECverify(h, sig, pub):
	r,s = sig
	if 0<r<N and 0<s<N and (N*pub).x()==None:
		u1 = h*mod_inv(s,N)%N
		u2 = r*mod_inv(s,N)%N
		checkP = u1*G + u2*pub
		if checkP.x()==r:
			return True
	return False

def getUnspent(address, testnet):
	network = 'BTCTEST' if testnet else 'BTC'
	response = requests.get('https://chain.so/api/v2/get_tx_unspent/'+network+'/'+address).json()
	utxos = response['data']['txs']
	clean_utxos = [{'value':int(float(i['value'])*100000000), 'index':i['output_no'], 'txid':i['txid']} for i in utxos]
	return clean_utxos

def pushTX(tx, testnet=False):
	data = {'tx_hex':tx}
	network = 'BTCTEST' if testnet else 'BTC'
	response = requests.post('https://chain.so/api/v2/send_tx/'+network, data=data)
	return response.json()

def convert_single_input(input_):
	prev_index_padded = "".join(["0" for i in range(8-len(hex(input_['index'])[2:]))])+hex(input_['index'])[2:]
	prev_index_endian = "".join(list(reversed([prev_index_padded[2*i:2*(i+1)] for i in range(len(prev_index_padded)/2)]))) 
	prev_tx_hash_r = "".join(list(reversed([input_['txid'][2*i:2*(i+1)] for i in range(len(input_['txid'])/2)])))
	collected_input_data = prev_tx_hash_r + prev_index_endian
	return collected_input_data

def convert_single_output(output_):
	output_value_padded = "".join(["0" for i in range(16-len(hex(output_['value'])[2:]))])+hex(output_['value'])[2:]
	output_value_endian = "".join(list(reversed([output_value_padded[2*i:2*(i+1)] for i in range(len(output_value_padded)/2)])))
	collected_output_data = output_value_endian+'1976a914'+b58decode(output_['address'])+'88ac'
	return collected_output_data

def choose_inputs(utxos, amount, policy='basic'):
	tx_inputs = []
	try:
		if policy == 'all':
			return utxos
		elif policy == 'basic':
			utxos = sorted(utxos, key=itemgetter('value'), reverse=True)
		elif policy == 'small_first':
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

def unsigned_tx(address, outputs, satoshi_fee, change_address=None, testnet=False, utxo_policy='basic'):
	gross_input_thresh = sum([i['value'] for i in outputs]) + satoshi_fee
	utxos = getUnspent(address, testnet)
	total = sum([i['value'] for i in utxos])
	if total<gross_input_thresh:
		return -1
	tx_inputs = choose_inputs(utxos, gross_input_thresh, policy=utxo_policy)
	tx_outputs = outputs
	gross_input = sum([i['value'] for i in tx_inputs])
	change_address = change_address if change_address!=None else address
	if gross_input > gross_input_thresh:
		tx_outputs.append({'value':gross_input - gross_input_thresh, 'address':change_address})
	n_inputs = int2hexbyte(len(tx_inputs))
	n_outputs = int2hexbyte(len(tx_outputs))
	if n_inputs==-1 or n_outputs == -1:
		print "Error: Max inputs/outputs is 256. Abort Tx."
		return -1
	bytes_ = '01000000'+n_inputs+"".join([convert_single_input(i)+'00ffffffff' for i in tx_inputs])+n_outputs+"".join([convert_single_output(i) for i in tx_outputs])+'00000000'
	return bytes_

def quick_unsigned_tx(from_, to_, satoshi_amount, satoshi_fee):
	outs = [{'value':satoshi_amount, 'address':to_}]
	if from_[0] == '1':
		testnet=False
	elif from_[0] in ['2', 'm', 'n']:
		testnet=True
	else:
		raise ValueError("Not a bitcoin address: %s" %from_)
	return unsigned_tx(from_, outs, satoshi_fee, testnet=testnet)

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

def get_txid(bytes_):
	return sha256(sha256(bytes_.decode('hex')).digest()).digest()[::-1].encode('hex')

def decode_tx(bytes_):
	readable = deserialize(bytes_)
	inputs_decoded = [{'address': blockexplorer.get_tx(i['outpoint']['hash']).outputs[i['outpoint']['index']].address, 'value' : blockexplorer.get_tx(i['outpoint']['hash']).outputs[i['outpoint']['index']].value, 'prev_hash':i['outpoint']['hash'], 'index':i['outpoint']['index'], 'script':i['script'], 'sequence':i['sequence']}for i in readable['ins']]
	outputs_decoded = [{'address' : hex_to_b58check(i['script'][6:-4]), 'value': i['value'], 'script':i['script']} for i in readable['outs']]
	all_addresses = list(set([i['address'] for i in inputs_decoded] + [j['address'] for j in outputs_decoded]))
	full_decode = {'addresses': all_addresses, 'version': readable['version'], 'size':len(bytes_)/2, 'fees': sum([i['value'] for i in inputs_decoded]) - sum([i['value'] for i in outputs_decoded]), 'locktime':readable['locktime'], 'inputs':inputs_decoded, 'outputs':outputs_decoded}
	return full_decode

def btc2sat(decimal):
	return int(decimal*100000000)

def txsize_est(from_, outputs):
	utxos = unspent(from_)
	gross_input_thresh = sum([i['value'] for i in outputs]) + 1000
	tx_inputs = choose_inputs(utxos, gross_input_thresh)
	bytes_est = 168*len(tx_inputs)+34*(len(outputs)+1) + 24
	return int(round(bytes_est/10.0)*10)

def int2hexbyte(int_):
	raw_hex = hex(int_)[2:]
	if len(raw_hex) == 1:
		byte_ = '0'+raw_hex
	elif len(raw_hex) == 2:
		byte_ = raw_hex
	else:
		raise ValueError("not interpretable as hex byte: %s" %int_)
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

def rs2DER(r,s):
	r=hex(r)[2:]
	s=hex(s)[2:]
	r = r if r[-1]!='L' else r[:-1]
	r = r if r[0] in [str(i) for i in range(1,8)] else '00'+r
	s = s if s[-1]!='L' else s[:-1]
	s = s if s[0] in [str(i) for i in range(1,8)] else '00'+s
	r_len=hex(len(r)/2)[2:]
	s_len=hex(len(s)/2)[2:]
	sig = '02'+r_len+r+'02'+s_len+s
	sig_len=hex(len(sig)/2)[2:]
	sigScript='30'+sig_len+sig+'01'
	script_len=hex(len(sigScript)/2)[2:]
	return script_len+sigScript

def rawSig2ScriptSig(sig, pubkey):
	r,s = sig
	sig=rs2DER(r,s)
	sig=sig+hex(len(pubkey)/2)[2:] + pubkey	
	sig_len=hex(len(sig)/2)[2:]
	return sig_len+sig+'ffffffff'
