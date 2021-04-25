# Cryptodrome Library
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Python Modules
from base64 import b64encode, b64decode
import json

'''
initEncryptionScheme()
	* opens the configuration file
	* parses parameters into dictionary
'''
def initEncryptionScheme():
  global encryption_scheme
 
  with open('config_file') as config_file:
    encryption_scheme = json.load(config_file)
    print("initEncryptionScheme()")

def getPlaintext():
  print("getPlain"", encryption_scheme['filePath'])
  with open(encryption_scheme['filePath'],"rb") as f:
    plaintext = f.read()
    print(plaintext)

'''
generateSalts()
  * masterSalt
  * encryptionSalt
  * hmacSalt
'''
def generateSalts():
  print("generateSalts()")
  print("Encryption Type: ", encryption_scheme['encryptionType'])
  print("Key Length: ", standard_block_size[encryption_scheme['encryptionType']])
  
  encryption_scheme['masterSalt'] = b64encode(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']]))
  encryption_scheme['encryptionSalt'] = b64encode(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']]))
  encryption_scheme['hmacSalt'] = b64encode(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']]))

'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* differntiate btw/ encryption/decryption based on config values
'''
def createMasterKey():
	print("createMasterKey()")
	if encryption_scheme['masterSalt'] == "none":
		print("Encryption Branch: ")
		generateSalts()
	else:
		print("Decryption Branch: ")

	return createKey(encryption_scheme['password'], encryption_scheme['count'], encryption_scheme['masterSalt'])

'''
createEncryptionKey(master_key, count=1)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count=1):
	return createKey(master_key, count, encryption_scheme['encryptionSalt'])

'''
createHmacKey(master_key, count=1)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key, count=1):
	return createKey(master_key, count, encryption_scheme['hmacSalt'])

'''
createKey(password, count)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password: str, count: int, salt: b''):
	dkLen = standard_block_size[encryption_scheme['encryptionType']]
	return PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_library[encryption_scheme['hashType']])

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_block_size = {"3DES": 8, "AES128": 16, "AES256": 32}

'''
variables tracking encryption session and preferences
'''
encryption_scheme = {}
master_key = b''
encryption_key = b''
hmac_key = b''
user_choice = ""
file_path = ""
password = ""

'''
main()-ish
	* Collect info from configuration file
	* Create master key
'''
initEncryptionScheme()
# master_key = createMasterKey()
# encryption_key = createEncryptionKey(master_key)
# hmac_key = createHmacKey(master_key)

# encryption_scheme['masterKey'] = b64encode(master_key)
# encryption_scheme['encryptionKey'] = b64encode(encryption_key)
# encryption_scheme['hmacKey'] = b64encode(hmac_key)

getPlaintext()




#  print("Encryption Scheme Type: ", type(encryption_scheme))
#     print("Config File Contents:\n", json.dumps(encryption_scheme, indent=1), end="\n\n")
# for key in encryption_scheme.keys():
#     print(key, "\t\t\t", encryption_scheme[key])
# print(master_key)
# print(encryption_key)
# print(hmac_key)