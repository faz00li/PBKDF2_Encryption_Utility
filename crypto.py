from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2

import json
# import Crypto.Hash.SHA256
# import Crypto.Hash.SHA512
# from Crypto.Hash import HMAC

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512

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
		# TODO make sure password is successfuly stored in schema
		# password = input('Enter password... ')
		# encryption_scheme['password'] = password

		print("ENCRYPTION SCHEME TYPE: ", type(encryption_scheme))

		print("Gathering encryption configuration sesttings: \n Encryption Scheme: ", json.dumps(encryption_scheme, indent=1), end="\n")

'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* passes the password and count paramete to createKey()
'''
def createMasterKey():
	# TODO ask user for password here
	# TODO remove password field from config file and here
	password = encryption_scheme['password']
	count = encryption_scheme['count']
	master_salt = get_random_bytes(16)
	human_master_salt = b64encode(master_salt).decode('utf-8')
	encryption_scheme['masterSalt'] = human_master_salt
	print("Master Salt: ", human_master_salt, end="\n")
	return createKey(password, count, master_salt)

'''
createEncryptionKey(master_key, count=1)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count=1):
	encryption_salt = get_random_bytes(16)
	human_encryption_salt = b64encode(encryption_salt).decode('utf-8')
	encryption_scheme['encryptionSalt'] = human_encryption_salt
	print("Encryption Salt: ", human_encryption_salt, end="\n")
	return createKey(master_key, count, encryption_salt)

'''
createHmacKey(master_key, count=1)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key, count=1):
	hmac_salt = get_random_bytes(16)
	human_hmac_salt = b64encode(hmac_salt).decode('utf-8')
	encryption_scheme['hmacSalt'] = human_hmac_salt
	print("HMAC Salt: ", human_hmac_salt, end="\n")
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
	hash_type = hash_library[encryption_scheme['hashType']]
	return PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_type)

'''
encryptDocument(encryption_key)
	* convert plaintext to byte arrey 
	* pad byte array to appropriate block size
	* encrypt document in manner specified by config schema w/ CBC mode
	* output IV and ciphertext to console
'''
def encryptDocument(encryption_key):
	# TODO pull from file -> encryption_scheme['filePath'], open file, etc.
	bytes_file_contents = encryption_scheme['instructions'].encode()

	cipher = AES.new(encryption_key, AES.MODE_CBC)
	# TODO paramaterize padding to appropriate encryption algorithm
	# TODO paramaterize encryption algorithm 
	bytes_ciphertext = cipher.encrypt(pad(bytes_file_contents, AES.block_size))
	human_iv = b64encode(cipher.iv).decode('utf-8')
	human_ciphertext = b64encode(bytes_ciphertext).decode('utf-8')
	
	encryption_scheme['iv'] = human_iv
	encryption_scheme['ciphertext'] = human_ciphertext

'''
authenticateMessage()
	* encryption scheme dictionary > to string > to bytes
	* derive HMAC and store in dictionary
'''
def authenticateMessage():
	h = HMAC.new(hmac_key, digestmod=SHA256)
	
	string_file_metadata = json.dumps(encryption_scheme)
	bytes_file_metadata = string_file_metadata.encode()
	h.update(bytes_file_metadata)
	encryption_scheme['HMAC: '] = h.hexdigest()
	

'''
encryptFile()
	* branch of code execution for file encryption
	* collects password from user
	* calls helper functions
'''
def encryptFile():
	initEncryptionScheme() 

	master_key = createMasterKey()
	encryption_key = createEncryptionKey(master_key)
	hmac_key = createHmacKey(master_key)

	print("Master Key: ", master_key, end='\n') 
	print("Encryption Key: ", encryption_key, end='\n')
	print("HMAC Key: ", hmac_key, end='\n')

	encryptDocument(encryption_key)
	
	authenticateMessage()

	print("Encryption Scheme: \n", json.dumps(encryption_scheme, indent=1, skipkeys=True), end="\n") 

'''
saveEncryptedFile()
	* does what it says on the tin
'''
def saveEncryptedFile():
	# TODO parse filePath to get file name to label new file
	open()



'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
# hash_library = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
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
encryptFile()








