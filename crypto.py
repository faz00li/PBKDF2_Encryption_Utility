# Cryptodrome Library
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Python Modules
import json
import binascii
import sys
import argparse

###############################################################################
# Salts can be strings or binary
# Keys must be binary
# Ciphertext must be binary
# Plaintext must be binary
# hmac digest returned as string - turn back into string after decryption
###############################################################################
DEBUG = True
DEBUG_INTERNAL = 1
DEBUG_INTERNAL_CREATE_KEY = 0
DEBUG_FINAL_FILE = 0
ENCRYPTION_BRANCH = True
DECRYPTION_BRANCH = False

MASTER_KEY = 1
ENCRYPTION_KEY = 2
HMAC_KEY = 3


# DEBUG_1 = True
# if DEBUG_1:
# 	if ENCRYPTION_BRANCH:
# 		print("Encryption Scheme: ", encryption_scheme, end='\n\n')
# 	if DECRYPTION_BRANCH:
# 		print("Decryption Scheme: ", decryption_scheme, end='\n\n')

###############################################################################
# Methods for both Encryption and Decryption
###############################################################################
'''
getArgs()
	* collect preferences from CLI
'''
def getArgs():
	print("getArgs()")
	parser = argparse.ArgumentParser(prog="PBKDF2 Encryption Utility", \
	usage="Program for encrypting and decrypting files. CLI input takes mode of operation, path to file, and the password.")

	parser.add_argument("mode", help="[ encrypt | decrypt ]")
	parser.add_argument("path", help="<file path>")
	parser.add_argument("password", help="<password>")

	args = parser.parse_args()

	global file_path, password, ENCRYPTION_BRANCH, DECRYPTION_BRANCH
	
	mode = args.mode
	file_path = args.path
	password = args.password

	DEBUG_0 = True
	if DEBUG_0:
		print(f"Mode: {mode}\nFile Path: {file_path}\nPassword: {password}", end="\n\n")

	if mode.upper() == 'ENCRYPT':
		ENCRYPTION_BRANCH = True
		print("Beginning Encryption", end='\n\n')
		
	if mode.upper() == 'DECRYPT':
		DECRYPTION_BRANCH = True
		print("Beginning Decryption", end='\n\n')

'''
createKey(password, salt, dkLen, count, hmac_hash_module=hash_mod)
	* generate a single key, dictated by args, that can be used as a:
		> session master key
		> document encryption key
		> message authentication key
'''
def createKey(password, salt, dkLen, count, hash_mod, key_type):
	print("createKey()")

	DEBUG_0 = True
	if DEBUG_0:
		print("Password: ", password)
		print('Salt: ', salt)
		print("Desired Key Length: ", dkLen)
		print("Count: ", count)
		print("Encryption Type: ", hash_mod.__name__, end='\n\n')

	key = PBKDF2(password, salt, dkLen, count, hmac_hash_module=hash_mod)

	DEBUG_1 = True
	if DEBUG_1:
		if key_type == MASTER_KEY:
			print("Master Key Type: ", type(key))
			print("Master Key: ", key, end='\n\n')
		if key_type == ENCRYPTION_KEY:
			print("Encryption Key Type: ", type(key))
			print("Encryption Key: ", key, end='\n\n')
		if key_type == HMAC_KEY:
			print("HMAC Key Type: ", type(key))
			print("HMAC Key: ", key, end='\n\n')
	
	return key


###############################################################################
# Encryption Methods 
###############################################################################
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

	config_file.close()

	DEBUG = True
	if DEBUG:
		print("Initial Encryption Scheme: ", encryption_scheme, end='\n\n')
		
'''
getPlaintext()
	* obtain file in raw bytes
'''
def getPlaintext():
	print("getPlaintext()")

	with open(file_path,"rb") as f:
		plaintext = f.read()
	
	f.close()

	DEBUG = True
	if DEBUG:
		print("Plaintext:\n", plaintext, end='\n\n')

	return plaintext
	
'''
generateSalts()
  * masterSalt
  * encryptionSalt
  * hmacSalt
'''
def generateSalts(block_size):
	print("generateSalts(block_size)")
	
	global encryption_scheme

	encryption_scheme['masterSalt'] = get_random_bytes(block_size)
	encryption_scheme['encryptionSalt']  = get_random_bytes(block_size)
	encryption_scheme['hmacSalt']  = get_random_bytes(block_size)

	DEBUG = True
	if DEBUG:
		print("Desired Salt Length: ", block_size)
		print("Master Salt Type: ", type(encryption_scheme['masterSalt']))
		print("Master Salt: ", encryption_scheme['masterSalt'])
		print("Encryption Salt Type: ", type(encryption_scheme['encryptionSalt']))
		print("Encryption Salt: ", encryption_scheme['encryptionSalt'])
		print("HMAC Salt Type: ", type(encryption_scheme['hmacSalt']))
		print("HMAC Salt: ", encryption_scheme['hmacSalt'], end='\n\n')
		
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

	DEBUG = True
	if DEBUG:
		print("IV Type: ", type(iv))
		print("IV: ", iv, end='\n\n')

		print("Ciphertext Type: ", type(ciphertext))
		print("Ciphertext:\n", ciphertext, end='\n\n')

	return iv, ciphertext
	# TODO 3DES

'''
authenticateEncryption()
	* iv + ciphertext > to string > to bytes
	* derive HMAC from bytes
	* store HMAC in dictionary
'''
def authenticateEncryption(hmac_key, iv_ciphertext, hash_mod):
	print("authenticateEncryption()")
	h = HMAC.new(hmac_key, digestmod=hash_mod)
	h.update(iv_ciphertext)
	hmac = h.digest()

	DEBUG = True
	if DEBUG:
		print("HMAC Type:", type(hmac))
		print("HMAC:", hmac, end='\n\n')

	return hmac

'''
addHeader(master_key, encryption_key, hmac_key, iv_ciphertext)
	* add header to ciphertext
	* return header and ciphertext as string 
'''
def addHeader(hmac: bytes, s_kdf: str, i_count: int, iv: bytes, s_encryptionType: str, s_hashType: str, masterSalt: bytes, encryptionSalt: bytes, hmacSalt: bytes):
	print("addHeader()")

	head_delim = bytes("_", "UTF-8")
	ciph_delim = bytes("???", "UTF-8")
	kdf = bytes(s_kdf, "UTF-8")
	count = bytes(str(i_count), "UTF-8")
	encryptionType = bytes(s_encryptionType, "UTF-8")
	hashType = bytes(s_hashType, "UTF-8")

	header = hmac + head_delim + kdf + head_delim + count + head_delim + iv + head_delim + encryptionType + head_delim + \
		hashType + head_delim + masterSalt + head_delim + encryptionSalt + head_delim + hmacSalt + ciph_delim
	
	DEBUG = True
	if DEBUG:
		print("Header:\n", header, end="\n\n")
	
	# bet
	DEBUG_DIAGNOSTIC = True
	
	
	return header

'''
getFileName()
	* returns name of encrypted file
'''
def getFileName():
	print("getFileName()")
	file_path_tokens = file_path.split("/")
	file_name = file_path_tokens[len(file_path_tokens) -1]
	file_name = file_name + ".enc" 
	
	DEBUG = True
	if DEBUG:
		print("File Name:", file_name)
	
	return file_name
		
'''
saveEncryptedFile()
'''
def saveEncryptedFile(final_file):
	print("saveEncryptedFile()")
	file_name = getFileName()

	DEBUG = True
	if DEBUG:
		print("File Name:", file_name)
		print("Final File Type: ", type(final_file), end='\n\n')
		print("Final File:\n", final_file, end='\n\n')

	with open(file_name, "wb") as f:
		f.write(final_file)
	f.close()

###############################################################################
# Decryption Utility Methods
###############################################################################
'''
initDecryptionScheme()
	* read decryption configuration settings from file
	* read raw encrypted doc from file
	* split raw doc into meta data and the file
	* split meta data into fields
	* create two dictionaries 1) byte meta data fields 2) string meta data fields
'''
def initDecryptionScheme():
	print("initDecryptionScheme()")

	global decryption_scheme
	global decryption_scheme_bytes

	with open('config_file_decryption') as config_file:
		conf_scheme = json.load(config_file)
		
	with open(conf_scheme['filePath'], "rb") as encrypted_file:
		encrypted_doc = encrypted_file.read()

	meta_cipher = encrypted_doc.split(bytes("???", "UTF-8"))

	meta = meta_cipher[0].split(bytes("_", "UTF-8"))
	decryption_scheme_bytes = dict(zip(header_params, meta))
	decryption_scheme_bytes['cipherext'] = meta_cipher[1]

	meta_string = []
	for x in meta:
		meta_string.append(x.decode())
	
	decryption_scheme = dict(zip(header_params, meta_string))
	decryption_scheme['password'] = conf_scheme['password']

	DEBUG = False
	if DEBUG:
		print("Decryption Scheme: ", conf_scheme, end='\n\n')
		print("Encrypted Doc Type: ", type(encrypted_doc), end='\n\n')
		# print("Encrypted Doc: \n", encrypted_doc)
		print("Meta of Meta Cipher Type: ", type(meta_cipher[0]))
		print("Meta of Meta Cipher: ", meta_cipher[0], end='\n\n')
		print("Meta String: ", meta_string, end='\n\n')
		print("Decryption Scheme: ", decryption_scheme_bytes, end='\n\n')
		print("Decryption Scheme:\n", decryption_scheme, end='\n\n')

'''
verifyHmac()
'''
def verifyHmac(master_key):
	h = HMAC.new(master_key, digestmod=hash_library[decryption_scheme['hashType']])
	h.update(decryption_scheme_bytes['iv'] + decryption_scheme_bytes['ciphertext'])
	try:
		h.hexverify(decryption_scheme['HMAC']) #TODO fix hexvrify to verify
		print("The message '%s' is authentic" % msg)
	except ValueError:
		print("The message or the key is wrong")

###############################################################################
# Variables tracking encryption and decryption session settings and preferences
###############################################################################

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_block_size = {"3DES": 8, "AES128": 16}

header_params = ["HMAC", "KDF", "count", "iv", "encryptionType", "hashType", "masterSalt", "encryptionSalt", "hmacSalt"]
encryption_scheme = {}
decryption_scheme = {}
decryption_scheme_bytes = {}
password = ""
file_path = ""


###############################################################################
# Configure preferences from CLI and config files
###############################################################################
getArgs()

DEBUG_0 = False
if DEBUG_0:
	print(f"From Main()\nFile Path: {file_path}\nPassword: {password}", end="\n\n")

###############################################################################
# Encryption Program Flow
###############################################################################
if ENCRYPTION_BRANCH:
	initEncryptionScheme()

	block_size = standard_block_size[encryption_scheme['encryptionType']]
	hash_mod = hash_library[encryption_scheme['hashType']]

	plaintext = getPlaintext()
	generateSalts(block_size)

	master_key = createKey(password, encryption_scheme['masterSalt'], block_size, encryption_scheme['count'], hash_mod, MASTER_KEY)
	encryption_key = createKey(password, encryption_scheme['encryptionSalt'], block_size, 1, hash_mod, ENCRYPTION_KEY)
	hmac_key = createKey(password, encryption_scheme['hmacSalt'], block_size, 1, hash_mod, HMAC_KEY)

	iv, ciphertext = encryptDocument(encryption_key, plaintext)
	iv_ciphertext = iv + ciphertext

	hmac = authenticateEncryption(hmac_key, iv_ciphertext, hash_mod)

	encryption_scheme['HMAC'] = hmac
	encryption_scheme['iv'] = binascii.hexlify(iv).decode()
# aleph
	header = addHeader(hmac, encryption_scheme['KDF'], encryption_scheme['count'], iv, encryption_scheme['encryptionType'], encryption_scheme['hashType'], \
		encryption_scheme['masterSalt'], encryption_scheme['encryptionSalt'], encryption_scheme['hmacSalt'])

	final_file = header + ciphertext

	saveEncryptedFile(final_file)



	DEBUG_1 = False
	if DEBUG_1:
		print("SUMMARY DEBUG")
		print("Plaintext Type: ", type(plaintext))
		print("Plaintext:\n", plaintext, end='\n\n')

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

		print("Final File Type: ", final_file)

	



'''
###############################################################################
# Decryption Program Flow 
###############################################################################
if DECRYPTION_BRANCH:

	initDecryptionScheme()

	DEBUG = False
	if DEBUG:
		print("From Main:\n")
		print("Decryption Scheme Bytes:\n", decryption_scheme_bytes, end='\n\n')
		print("Decryption Scheme:\n", decryption_scheme, end='\n\n')
	
	master_key = createMasterKey()
	# print("Master Key: ", master_key)
	verifyHmac(master_key)
'''	



	

	





