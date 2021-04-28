# Cryptodrome Library
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Python Modules
import json
import binascii

DEBUG = 0
DEBUG_INTERNAL = 0
DEBUG_INTERNAL_CREATE_KEY = 0
DEBUG_FINAL_FILE = 1

'''
initEncryptionScheme()
	* opens the configuration file
	* parses parameters into dictionary
'''
def initEncryptionScheme():
	print("initEncryptionScheme()")

	global encryption_scheme

	with open('config_file') as config_file:
		encryption_scheme = json.load(config_file)

	if DEBUG_INTERNAL:
		print("Encryption Scheme: ", encryption_scheme, end='\n\n')
		
'''
getPlaintext()
	* obtain file in raw bytes
'''
def getPlaintext():
	print("getPlaintext()")

	with open(encryption_scheme['filePath'],"rb") as f:
		plaintext = f.read()

	if DEBUG_INTERNAL:
		print("Plaintext: ", plaintext, end='\n\n')

	return plaintext
	
'''
generateSalts()
  * masterSalt
  * encryptionSalt
  * hmacSalt
'''
def generateSalts():
	print("generateSalts()")

	if DEBUG_INTERNAL:
		print("Encryption Type: ", encryption_scheme['encryptionType'])
		print("Key Length: ", standard_block_size[encryption_scheme['encryptionType']])

	encryption_scheme['masterSalt'] = binascii.hexlify(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']])).decode()
	encryption_scheme['encryptionSalt'] = binascii.hexlify(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']])).decode()
	encryption_scheme['hmacSalt'] = binascii.hexlify(get_random_bytes(standard_block_size[encryption_scheme['encryptionType']])).decode()

	if DEBUG_INTERNAL:
		print("Master Salt Type: ", type(encryption_scheme['masterSalt']))
		print("Master Salt: ", encryption_scheme['masterSalt'])
		print("Encryption Salt Type: ", type(encryption_scheme['encryptionSalt']))
		print("Encryption Salt: ", encryption_scheme['encryptionSalt'])
		print("HMAC Salt Type: ", type(encryption_scheme['hmacSalt']))
		print("HMAC Salt: ", encryption_scheme['hmacSalt'], end='\n\n')
		
'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* differntiate btw/ encryption/decryption based on config values
'''
def createMasterKey():
	print("createMasterKey()")
	if encryption_scheme['masterSalt'] == "none":
		print("Encryption Branch: ", end="\n\n")
		generateSalts()
	else:
		print("Decryption Branch: ")

	master_key = createKey(encryption_scheme['password'], encryption_scheme['count'], encryption_scheme['masterSalt'])
	
	if DEBUG_INTERNAL:
		print("Master Key Type: ", type(master_key))
		print("Master Key: ", master_key, end='\n\n')
	
	return master_key
		
'''
createEncryptionKey(master_key, count=1)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count=1):
	print("createEncryptionKey()")

	encryption_key = createKey(master_key, count, encryption_scheme['encryptionSalt'])
	
	if DEBUG_INTERNAL:
		print("Encryption Key Type: ", type(encryption_key))
		print("Encryption Key: ", encryption_key, end='\n\n')

	return encryption_key

'''
createHmacKey(master_key, count=1)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key, count=1):
	print("createHmacKey()")
	
	hmac_key = createKey(master_key, count, encryption_scheme['hmacSalt'])
	
	if DEBUG_INTERNAL:
		print("HMAC Key Type: ", type(hmac_key))
		print("HMAC Key: ", hmac_key, end='\n\n')

	return hmac_key

'''
createKey(password, count)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password: str, count: int, salt: b''):
	print("createKey()")
	dkLen = standard_block_size[encryption_scheme['encryptionType']]

	if DEBUG_INTERNAL_CREATE_KEY:
		print("Desired Key Length: ", dkLen)

	key = PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_library[encryption_scheme['hashType']])

	if DEBUG_INTERNAL_CREATE_KEY:
		print("Generic Key Type: ", type(key))
		print("Generic Key: ", key, end='\n\n')
	
	return key

'''
encryptDocument(encryption_key)
	* convert plaintext to byte arrey 
	* pad byte array to appropriate block size
	* encrypt document in manner specified by config schema w/ CBC mode
	* output IV and ciphertext to console
'''
def encryptDocument(encryption_key, plaintext):
	print("encryptDocument()")

	cipher = AES.new(encryption_key, AES.MODE_CBC)
	ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
	iv = cipher.iv

	if DEBUG_INTERNAL:

		print("IV Type: ", type(iv))
		print("IV: ", iv, end='\n\n')

		print("Ciphertext Type: ", type(ciphertext))
		print("Ciphertext: ", ciphertext, end='\n\n')

	return iv, ciphertext
	# TODO 3DES

'''
authenticateEncryption()
	* iv + ciphertext > to string > to bytes
	* derive HMAC from bytes
	* store HMAC in dictionary
'''
def authenticateEncryption(hmac_key, iv_ciphertext):
	print("authenticateEncryption()")
	h = HMAC.new(hmac_key, digestmod=hash_library[encryption_scheme['hashType']])
	h.update(iv_ciphertext)
	hmac = h.hexdigest()

	if DEBUG_INTERNAL:
		print("HMAC Type:", type(hmac))
		print("HMAC:", hmac, end='\n\n')

	return hmac

'''
addHeader(master_key, encryption_key, hmac_key, iv_ciphertext)
	* add header to ciphertext
	* return header and ciphertext as string 
'''
def addHeader():
	print("addHeader()")

	hpd = "_"
	cd = "???"
	
	finalFile = encryption_scheme['HMAC'] + hpd + encryption_scheme['kdf'] + hpd + str(encryption_scheme['count']) + hpd + encryption_scheme['iv'] \
		+ hpd + encryption_scheme['encryptionType'] + hpd + encryption_scheme['hashType'] + hpd + encryption_scheme['masterSalt'] + hpd \
			 + encryption_scheme['encryptionSalt'] + hpd + encryption_scheme['hmacSalt'] + cd + encryption_scheme['ciphertext']
	
	return finalFile

'''
saveEncryptedFile()
'''
def saveEncryptedFile():
	# TODO parse filePath to get file name to label new file
	file_name = "encrypted_file"
	encrypted_file = json.dumps(encryption_scheme)

	with open(file_name, "wb") as ef:
		ef.write(encrypted_file)

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_block_size = {"3DES": 8, "AES128": 16}

'''
variables tracking encryption session and preferences
'''
encryption_scheme = {}

'''
main()-ish
	* Collect info from configuration file
	* Create master key
'''
initEncryptionScheme()
plaintext = getPlaintext()
master_key = createMasterKey()
encryption_key = createEncryptionKey(master_key)
hmac_key = createHmacKey(master_key)
iv, ciphertext = encryptDocument(encryption_key, plaintext)
iv_ciphertext = iv + ciphertext
hmac = authenticateEncryption(hmac_key, iv_ciphertext)

if DEBUG:
	print("FULL DEBUG")
	print("Plaintext Type: ", type(plaintext))
	print("Plaintext: ", plaintext, end='\n\n')

	print("Master Key Type: ", type(master_key))
	print("Master Key: ", master_key, end='\n\n')

	print("Encryption Key Type: ", type(encryption_key))
	print("Encryption Key: ", encryption_key, end='\n\n')

	print("HMAC Key Type: ", type(hmac_key))
	print("HMAC Key: ", hmac_key, end='\n\n')

	print("IV Type: ", type(iv))
	print("IV: ", iv, end='\n\n')

	print("Ciphertext Type: ", type(ciphertext))
	print("Ciphertext: ", ciphertext, end='\n\n')

	print("HMAC Type: ", type(hmac))
	print("HMAC: ", hmac, end='\n\n')

encryption_scheme['HMAC'] = hmac
encryption_scheme['iv'] = binascii.hexlify(iv).decode()
encryption_scheme['ciphertext'] = binascii.hexlify(ciphertext).decode()

finalFile = addHeader()

if DEBUG_FINAL_FILE:
	print("Final File: \n", finalFile, end='\n\n')






#  print("Encryption Scheme Type: ", type(encryption_scheme))
#     print("Config File Contents:\n", json.dumps(encryption_scheme, indent=1), end="\n\n")
# for key in encryption_scheme.keys():
#     print(key, "\t\t\t", encryption_scheme[key])
# print(master_key)
# print(encryption_key)
# print(hmac_key)

########################################
# Salts can be strings or binary
# Keys must be  binary
# Ciphertext must be binary
# Plaintext must be binary