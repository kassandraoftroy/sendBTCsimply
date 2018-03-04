import ecdsa
from ecdsa import SigningKey, SECP256k1


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
		signingkey = ecdsa.SigningKey.from_string(b58check_to_hex(private_key).decode('hex'), curve=SECP256k1)
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