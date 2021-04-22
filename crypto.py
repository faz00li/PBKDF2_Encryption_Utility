from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

import json
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

'''
initEncryptionScheme()
	* opens the configuration file
	* parses parameters into dictionary
	* prints schema contents to console
'''
def initEncryptionScheme():
	with open('config_file') as config_file:
		global encryption_scheme
		encryption_scheme = json.load(config_file)
	
	print(\
		"Password: \t\t" + encryption_scheme["password"],\
		"Encryption Standard: \t" + encryption_scheme["encryptionType"],\
		"Hash Type: \t\t" + encryption_scheme["hashType"],\
		"Iterations: \t\t" + str(encryption_scheme["count"]),\
		sep='\n', end='\n\n')

'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* passes the password and count paramete to createKey()
'''
def createMasterKey():
	password = encryption_scheme['password']
	count = encryption_scheme['count']
	return createKey(password, count)

'''
createEncryptionKey(master_key)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count = 1):
	return createKey(master_key, count)

'''
createHmacKey(master_key)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key):
	return createKey(master_key, count = 1)

'''
createKey(password, count)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password: str, count: int):
	salt = get_random_bytes(16)
	dkLen = standard_key_length[encryption_scheme['encryptionType']]
	print("KEY LENGTH: ", dkLen)
	hash_type = hash_library[encryption_scheme['hashType']]
	return PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_type)

'''
encryptDocument(encryption_key)
	* encrypt document in manner specified by config schema
'''
def encryptDocument(encryption_key):
	print("ENCRYPT DOCUMENT - ENCRYPTION KEY: ", encryption_key, end="\n\n")
	print("ENCRYPT DOCUMENT - TYPE: ", type(encryption_key), end="\n\n")
	print("ENCRYPT DOCUMENT - KEY LENGTH: ", len(encryption_key), end="\n\n")
	cipher = AES.new(encryption_key, AES.MODE_CBC)
	print("AES.block_size: ", AES.block_size)
	print("ENCRYPT DOCUMENT - PLAIN TEXT: ", encryption_scheme["instructions"], end="\n\n")
	b = bytearray()
	b.extend(map(ord, encryption_scheme["instructions"] ))
	print("ENCRYPT DOCUMENT - PLAIN TEXT IN BINARY: ", b, end="\n\n" )
	# TODO - get this printed in hex 
	ct_bytes = cipher.encrypt(pad(b, AES.block_size))
	iv = b64encode(cipher.iv).decode('utf-8')
	ct = b64encode(ct_bytes).decode('utf-8')
	result = json.dumps({'iv':iv, 'ciphertext':ct})
	print("\n\n", result)

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
# TODO changes AES128 from 128(possibly bytes not bits) to 16(bytes not bits)??#? - seems to have worked
# TODO change length of keys for hashes in dictionary
standard_key_length = {"3DES": 64, "AES128": 16, "AES256": 256}

'''
variables tracking encryption session keys
'''
master_key = b''
encryption_key = b''
hmac_key = b''
encryption_scheme = {}

'''
main()-ish
	* Collect info from configuration file
	* Create master key
'''
initEncryptionScheme() 
master_key = createMasterKey()
print("Master Key: ", master_key, end='\n\n') 

encryption_key = createEncryptionKey(master_key)
print("Encryption Key: ", encryption_key, end='\n\n')

hmac_key = createHmacKey(master_key )
print("HMAC Key: ", hmac_key, end='\n\n')

encryptDocument(encryption_key)







