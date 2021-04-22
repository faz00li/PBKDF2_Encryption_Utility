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

		print(json.dumps(encryption_scheme, indent=1, separators=("\n", ":")), end="\n\n")

'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* passes the password and count paramete to createKey()
'''
def createMasterKey():
	password = encryption_scheme['password']
	count = encryption_scheme['count']
	master_salt = get_random_bytes(16)
	human_master_salt = b64encode(master_salt).decode('utf-8')
	encryption_scheme["masterSalt"] = human_master_salt
	return createKey(password, count, master_salt)

'''
createEncryptionKey(master_key, count=1)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count=1):
	encryption_salt = get_random_bytes(16)
	human_encryption_salt = b64encode(encryption_salt).decode('utf-8')
	encryption_scheme["encryptionSalt"] = human_encryption_salt
	return createKey(master_key, count, encryption_salt)

'''
createHmacKey(master_key, count=1)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key, count=1):
	hmac_salt = get_random_bytes(16)
	human_hmac_salt = b64encode(hmac_salt).decode('utf-8')
	encryption_scheme["hmacSalt"] = human_hmac_salt
	return createKey(master_key, count, hmac_salt)

'''
createKey(password, count)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password: str, count: int, salt: b''):
	
	dkLen = standard_key_length[encryption_scheme['encryptionType']]
	print("KEY LENGTH: ", dkLen)
	hash_type = hash_library[encryption_scheme['hashType']]
	return PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_type)

# '''
# encryptDocument(encryption_key)
# 	* convert plaintext to byte arrey 
# 	* pad byte array to appropriate block size
# 	* encrypt document in manner specified by config schema w/ CBC mode
# 	* output IV and ciphertext to console
# '''
# def encryptDocument(encryption_key):
# 	bytes_plaintext = encryption_scheme['instructions'].encode()

# 	# TODO remove development code de-bugging
# 	print("ENCRYPTING DOCUMENT:")
# 	print("Key: \t\t\t", encryption_key)
# 	print("Key Type: \t\t", type(encryption_key))
# 	print("Key Length: \t\t", len(encryption_key))
# 	print("Plain Text: ", encryption_scheme["instructions"], end="\n\n")
# 	print("Plain Text in Binary: ", bytes_plaintext)

# 	cipher = AES.new(encryption_key, AES.MODE_CBC)
# 	# TODO paramaterize padding to appropriate encryption algorithm
# 	# TODO paramaterize encryption algorithm 
# 	bytes_ciphertext = cipher.encrypt(pad(bytes_plaintext, AES.block_size))
# 	human_iv = b64encode(cipher.iv).decode('utf-8')
# 	human_ciphertext = b64encode(bytes_ciphertext).decode('utf-8')
# 	result = json.dumps({'iv':human_iv, 'ciphertext':human_ciphertext})
# 	print("\n\n", result)
# 	# TODO create object to return

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
standard_key_length = {"3DES": 8, "AES128": 16, "AES256": 32}

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

hmac_key = createHmacKey(master_key)
print("HMAC Key: ", hmac_key, end='\n\n')

print("AMENDED DICTIONARY:", encryption_scheme)

# encryptDocument(encryption_key)







