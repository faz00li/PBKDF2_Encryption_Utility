# Cryptodrome Library
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Python Modules
import json
import binascii

DEBUG = True
DEBUG_INTERNAL = 1
DEBUG_INTERNAL_CREATE_KEY = 0
DEBUG_FINAL_FILE = 0
ENCRYPTION_BRANCH = False
DECRYPTION_BRANCH = True

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

	head_delim = "_"
	ciph_delim = "???"
	
	header = encryption_scheme['HMAC'] + head_delim + encryption_scheme['kdf'] + head_delim + str(encryption_scheme['count']) + head_delim + encryption_scheme['iv'] \
		+ head_delim + encryption_scheme['encryptionType'] + head_delim + encryption_scheme['hashType'] + head_delim + encryption_scheme['masterSalt'] + head_delim \
			 + encryption_scheme['encryptionSalt'] + head_delim + encryption_scheme['hmacSalt'] + ciph_delim
	
	if DEBUG_INTERNAL:
		print("Final Header: ", header)
	
	return header

'''
getFileName()
	* returns name of encrypted file
'''
def getFileName():
	print("getFileName()")
	filePathTokens = encryption_scheme['filePath'].split("/")
	fileName = filePathTokens[len(filePathTokens) -1]
	fileName = fileName + ".enc" 
	
	return fileName
		
'''
saveEncryptedFile()
'''
def saveEncryptedFile(finalFile):
	file_name = getFileName()

	if DEBUG_INTERNAL:
		print("File Name:", file_name)
		print("Final File Type: ", type(finalFile))

	with open(file_name, "wb") as f:
		f.write(finalFile)

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
Encryption Branch
'''
if ENCRYPTION_BRANCH:
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

	header = addHeader()
	finalFile = bytes(header, "UTF-8") + ciphertext

	if DEBUG_FINAL_FILE:
		print("Header Type: ", type(header))
		print("Header: ", header)
		print("Final File: \n", finalFile, end='\n\n')

		# encryption_scheme['ciphertext'] = binascii.hexlify(ciphertext).decode()
		# encryption_scheme['masterKey'] = binascii.hexlify(master_key).decode()
		# encryption_scheme['encryptionKey'] = binascii.hexlify(master_key).decode()
		# encryption_scheme['hmacKey'] = binascii.hexlify(master_key).decode()
		# encryption_scheme['plainText'] = binascii.hexlify(plaintext).decode()
		# finalFileJson = json.dumps(encryption_scheme)
		# for key in encryption_scheme.keys():
		# 	print(key) TODO mess around if needed to compare
		# print("JSON: ", finalFileJson)

	saveEncryptedFile(finalFile)

#######################################################################
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
	decryption_scheme_bytes = dict(zip(decryption_params, meta))
	decryption_scheme_bytes['cipherText'] = meta_cipher[1]

	meta_string = []
	for x in meta:
		meta_string.append(x.decode())
	
	decryption_scheme = dict(zip(decryption_params, meta_string))

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

# '''
# verifyHmac()
# '''
# def verifyHmac():
# 	h = HMAC.new(decryption_scheme_bytes['hmacKey'], digestmod=hash_library[decryption_scheme['hashType']])
# 	h.update(decryption_scheme_bytes['iv'] + decryption_scheme_bytes['ciphertext'])
# 	try:
# 		h.hexverify(decryption_scheme['HMAC'])
# 		print("The message '%s' is authentic" % msg)
# 	except ValueError:
# 		print("The message or the key is wrong")

if DECRYPTION_BRANCH:
	'''
	variables tracking encryption session and preferences
	'''
	decryption_params = ["HMAC", "KDF", "count", "iv", "encryptionType", "hashType", "masterSalt", "encryptionSalt", "hmacSalt"]
	decryption_scheme = {}
	decryption_scheme_bytes = {}

	initDecryptionScheme()

	DEBUG = False
	if DEBUG:
		print("From Main:\n")
		print("Decryption Scheme Bytes:\n", decryption_scheme_bytes, end='\n\n')
		print("Decryption Scheme:\n", decryption_scheme, end='\n\n')
		
	# verifyHmac()
	

	

	

	





########################################
# Salts can be strings or binary
# Keys must be binary
# Ciphertext must be binary
# Plaintext must be binary