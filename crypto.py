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
import filecmp

###############################################################################
# Salts can be strings or binary
# Keys must be binary
# Ciphertext must be binary
# Plaintext must be binary
# hmac digest returned as bytes
###############################################################################
# Regulate operation mode
ENCRYPTION_BRANCH = True
DECRYPTION_BRANCH = False

# Types of keys used w/ KDF
MASTER_KEY = 1
ENCRYPTION_KEY = 2
HMAC_KEY = 3

# Header filed and ciphertext delimiters in encrypted file
HD = bytes("_", "UTF-8")
CD = bytes("???", "UTF-8")

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
		DECRYPTION_BRANCH = False
		print("Beginning Encryption", end='\n\n')
		
	if mode.upper() == 'DECRYPT':
		DECRYPTION_BRANCH = True
		ENCRYPTION_BRANCH = False
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

	global e_scheme

	with open('config_file') as config_file:
		e_scheme = json.load(config_file)

	config_file.close()

	DEBUG = True
	if DEBUG:
		print("Initial Encryption Scheme: ", e_scheme, end='\n\n')
		
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
  * mSalt
  * eSalt
  * hSalt
'''
def generateSalts(block_size):
	print("generateSalts(block_size)")

	global e_scheme

	e_scheme['mSalt'] = get_random_bytes(block_size)
	e_scheme['eSalt']  = get_random_bytes(block_size)
	e_scheme['hSalt']  = get_random_bytes(block_size)

	DEBUG = True
	if DEBUG:
		print("Desired Salt Length: ", block_size)
		print("Master Salt Type: ", type(e_scheme['mSalt']))
		print("Master Salt: ", e_scheme['mSalt'])
		print("Encryption Salt Type: ", type(e_scheme['eSalt']))
		print("Encryption Salt: ", e_scheme['eSalt'])
		print("HMAC Salt Type: ", type(e_scheme['hSalt']))
		print("HMAC Salt: ", e_scheme['hSalt'], end='\n\n')
		
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
	ciphertext = cipher.encrypt(pad(plaintext, AES.block_size)) #TODO paramaterize
	iv = cipher.iv

	DEBUG = False
	if DEBUG:
		print("IV Type: ", type(iv))
		print("IV: ", iv, end='\n\n')

		print("Ciphertext Type: ", type(ciphertext))
		print("Ciphertext:\n", ciphertext, end='\n\n')
		# Prints whole document

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
formatHeaderFields():
	* Convert all header fileds to bytes and store in dictionary
'''
def formatHeaderFields(hmac: bytes, s_kdf: str, i_count: int, iv: bytes, s_eType: str, s_hType: str, mSalt: bytes, eSalt: bytes, hSalt: bytes):
	print("formatHeaderFields()\n")

	global h_fields

	kdf = bytes(s_kdf, "UTF-8")
	count = bytes(str(i_count), "UTF-8")
	eType = bytes(s_eType, "UTF-8")
	hType = bytes(s_hType, "UTF-8")

	h_fields['HMAC'] = hmac
	h_fields['KDF'] = kdf
	h_fields['count'] = count
	h_fields['iv'] = iv
	h_fields['eType'] = eType
	h_fields['hType'] = hType
	h_fields['mSalt'] = mSalt
	h_fields['eSalt'] = eSalt
	h_fields['hSalt'] = hSalt

	DEBUG = True
	if DEBUG:
		for key in h_fields.keys():
			print(key, " ", h_fields[key])
		print("\n")

'''
getHeader(master_key, encryption_key, hmac_key, iv_ciphertext)
	* add header to ciphertext
	* return header and ciphertext as string 
'''
def getHeader(hmac: bytes, s_kdf: str, i_count: int, iv: bytes, s_eType: str, s_hType: str, mSalt: bytes, eSalt: bytes, hSalt: bytes):
	print("getHeader()")

	header = h_fields['HMAC'] + HD + h_fields['KDF'] + HD + h_fields['count'] + HD + h_fields['iv'] + HD + \
				h_fields['eType'] + HD + h_fields['hType'] + HD + h_fields['mSalt'] + HD + h_fields['eSalt'] + HD + \
						h_fields['hSalt'] + CD
	
	DEBUG = True
	if DEBUG:
		print("Header:\n", header, end="\n\n")
	
	return header

'''
getFileName()
	* returns name of encrypted file
'''
def getFileName():
	print("getFileName()\n")

	file_path_tokens = file_path.split("/")
	file_name = file_path_tokens[len(file_path_tokens) -1]
	x = file_name.rfind(".enc")
	if x != -1:
		file_name = file_name[:x + 1]

	DEBUG = True
	if DEBUG:
		print("File Name:", file_name)
	
	return file_name
		
'''
saveFile()
'''
def saveFile(final_file, mode):
	print("saveFile()")
	file_name = getFileName()

	if mode == ENCRYPTION_BRANCH:
		file_name = file_name + ".enc"
	
	if mode == DECRYPTION_BRANCH:
		file_name = file_name + ".dec"

	DEBUG = False
	if DEBUG:
		print("File Name:", file_name)
		print("Final File Type: ", type(final_file), end='\n\n')
		print("Final File:\n", final_file, end='\n\n')
		# This prints whole file

	with open(file_name, "wb") as f:
		f.write(final_file)
	f.close()
# bet
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
	print("initDecryptionScheme()\n")

	global d_scheme

	with open(file_path, "rb") as encrypted_file:
		e_doc = encrypted_file.read()
		encrypted_file.close()

	meta_cipher = e_doc.split(CD)

	meta = meta_cipher[0].split(HD)
	d_scheme = dict(zip(header_params, meta))

	original_stdout = sys.stdout

	with open("header_diagnostics_decryption.log", "w") as f:
		sys.stdout = f
		for key in d_scheme.keys():
			print(key, "->", d_scheme[key])
		f.close()
	
	sys.stdout = original_stdout
	d_scheme['cText'] = meta_cipher[1]

	DEBUG_DECRYPTION_SCHEME = True
	if DEBUG_DECRYPTION_SCHEME:
		print("Decryption Scheme:")
		for key in d_scheme.keys():
			if key == 'cText':
				break
			print(f"{key}:\t{d_scheme[key]}")
		print()

'''
verifyHmac()
'''
def verifyHmac(hmac_key: bytes, iv_ciphertext: bytes, hmac, hash_mod):
	print("verifyHmac()\n")
	h = HMAC.new(hmac_key, digestmod=hash_mod)
	h.update(iv_ciphertext)
	try:
		h.verify(hmac)
		print("The message '%s' is authentic" % hmac)
	except ValueError:
		print("The message or the key is wrong. Program terminated.")
		exit(0)

'''
decryptDocument(e_key, iv, ciphertext)	
'''
def decryptDocument(e_key: bytes, iv: bytes, block_size: int, ciphertext: bytes):
	print("decryptDocument()\n")

	cipher = AES.new(e_key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(ciphertext)
	plaintext = unpad(plaintext, block_size)
	
	DEBUG_DECRYPT_DOCUMENT = False
	if DEBUG_DECRYPT_DOCUMENT:
		print("Plaintext:\n", plaintext)
	
	return plaintext

###############################################################################
# Variables tracking encryption and decryption session settings and preferences
###############################################################################
'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_block_size = {"3DES": 8, "AES128": 16}

h_fields = {}
header_params = ["HMAC", "KDF", "count", "iv", "eType", "hType", "mSalt", "eSalt", "hSalt"]
e_scheme = {}
d_scheme = {}
d_scheme = {}
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
	# Get encryption configuration settings and preferences
	initEncryptionScheme()
	
	# Get cipher block size and actual Python hash module
	e_scheme['bSize'] = standard_block_size[e_scheme['eType']]
	hash_mod = hash_library[e_scheme['hType']]

	# Extract plaintext
	e_scheme['pText'] = getPlaintext()

	# Generate Salts - written globally into scheme dictionary
	generateSalts(e_scheme['bSize'])

	# Create keys
	e_scheme['mKey'] = createKey(password, e_scheme['mSalt'], e_scheme['bSize'], e_scheme['count'], hash_mod, MASTER_KEY)
	e_scheme['eKey'] = createKey(e_scheme['mKey'], e_scheme['eSalt'], e_scheme['bSize'], 1, hash_mod, ENCRYPTION_KEY)
	e_scheme['hKey'] = createKey(e_scheme['mKey'], e_scheme['hSalt'], e_scheme['bSize'], 1, hash_mod, HMAC_KEY)

	# Encrypt file - obtain iv and ciphertext
	e_scheme['iv'], e_scheme['cText'] = encryptDocument(e_scheme['eKey'], e_scheme['pText'])

	# Authenticate hmac(iv + ciphertext)
	e_scheme['iv_cText'] = e_scheme['iv'] + e_scheme['cText']
	e_scheme['HMAC'] = authenticateEncryption(e_scheme['hKey'], e_scheme['iv_cText'], hash_mod)

	# Format header fields - written globally into header dictionary
	formatHeaderFields(e_scheme['HMAC'], e_scheme['KDF'], e_scheme['count'], e_scheme['iv'], e_scheme['eType'], e_scheme['hType'], \
		e_scheme['mSalt'], e_scheme['eSalt'], e_scheme['hSalt'])

	# Generate header
	e_scheme['header'] = getHeader(h_fields['HMAC'], h_fields['KDF'], h_fields['count'], h_fields['iv'], h_fields['eType'], h_fields['hType'], \
		h_fields['mSalt'], h_fields['eSalt'], h_fields['hSalt'])

	# Combine header and ciphertext into one file and save
	final_file = e_scheme['header'] + e_scheme['cText']
	saveFile(final_file, ENCRYPTION_BRANCH)

	# Additional debugging - log1: header log2: keys, strictly for debugging in production
	DEBUG_DIAGNOSTIC = False
	if DEBUG_DIAGNOSTIC:
		original_stdout = sys.stdout 

		with open('header_diagnostics_encryption.log', 'w') as f:
			sys.stdout = f 
			
			for key in h_fields.keys():
				print(key, "->", h_fields[key])
			
			sys.stdout = original_stdout 

			f.close()

		with open('key_diagnostics_encryption.log', 'w') as f:
			sys.stdout = f 
	
			print("HMAC: ", e_scheme['HMAC'])
			print("M_Key: ", e_scheme['mKey'])
			print("E_Key: ", e_scheme['eKey'])
			print("H_Key: ", e_scheme['hKey'])
			
			sys.stdout = original_stdout 

			f.close()


###############################################################################
# Decryption Program Flow 
###############################################################################
if DECRYPTION_BRANCH:

	initDecryptionScheme()

	# Additional debugging - log1: headers, strictly for debugging in production
	DEBUG_HEADER_DIAGNOSTICS = False
	if DEBUG_HEADER_DIAGNOSTICS:
		print("Encryption/Decryption Headers Match:", \
			filecmp.cmp("header_diagnostics_encryption.log", "header_diagnostics_decryption.log"), \
				end="\n\n")
	
	# Get cipher block size and actual Python hash module
	d_scheme['bSize'] = standard_block_size[str(d_scheme['eType'], "UTF-8")]
	hash_mod = hash_library[str(d_scheme['hType'], "UTF-8")]

	# Create keys
	d_scheme['mKey'] = createKey(password, d_scheme['mSalt'], d_scheme['bSize'], int(d_scheme['count']), hash_mod, MASTER_KEY)
	d_scheme['eKey'] = createKey(d_scheme['mKey'], d_scheme['eSalt'], d_scheme['bSize'], 1, hash_mod, ENCRYPTION_KEY)
	d_scheme['hKey'] = createKey(d_scheme['mKey'], d_scheme['hSalt'], d_scheme['bSize'], 1, hash_mod, HMAC_KEY)

	# Additional debugging - log2: keys, strictly for debugging in production
	DEBUG_KEY_DIAGNOSTICS = False
	if DEBUG_KEY_DIAGNOSTICS:
		with open('key_diagnostics_decryption.log', 'w') as f:
			
			original_stdout = sys.stdout 
			
			sys.stdout = f 

			print("HMAC: ", d_scheme['HMAC'])
			print("M_Key: ", d_scheme['mKey'])
			print("E_Key: ", d_scheme['eKey'])
			print("H_Key: ", d_scheme['hKey'])
			
			sys.stdout = original_stdout 

			f.close()

			print("Derived Keys Match: ", filecmp.cmp('key_diagnostics_encryption.log', 'key_diagnostics_decryption.log'))

	# Verify hmac(iv + ciphertext)
	d_scheme['iv_cText'] = d_scheme['iv'] + d_scheme['cText']
	d_scheme['auth'] = verifyHmac(d_scheme['hKey'], d_scheme['iv_cText'], d_scheme['HMAC'], hash_mod)

	# Decrypt ciphertext 
	d_scheme['pText'] = decryptDocument(d_scheme['eKey'], d_scheme['iv'], d_scheme['bSize'] ,d_scheme['cText'])

	#aleph
	saveFile(d_scheme['pText'], DECRYPTION_BRANCH)



'''
	DEBUG = False
	if DEBUG:
		print("From Main:\n")
		print("Decryption Scheme Bytes:\n", d_scheme, end='\n\n')
		print("Decryption Scheme:\n", d_scheme, end='\n\n')
	
	master_key = createMasterKey()
	# print("Master Key: ", master_key)
	verifyHmac(master_key)
'''	



	

	





