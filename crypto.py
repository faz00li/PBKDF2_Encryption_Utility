from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

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
		sep='\n')

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
createKey(password, count)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password: str, count: int):
	salt = get_random_bytes(16)
	dkLen = standard_key_length[encryption_scheme['encryptionType']]
	hash_type = hash_library[encryption_scheme['hashType']]
	return PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_type)

'''
Dictionaries of hash modules and info about encrytion standards.
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
standard_key_length = {"3DES": 64, "AES128": 128, "AES256": 256}

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

print("Master Key: ", master_key)







