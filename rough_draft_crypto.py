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
greeting()
	* collect user preferences, file path and password
'''
def greeting():
	global password
	global file_path
	
	user_choice = input("Which would you like to do: \n 1) Enrypt File \n 2) Decrypt File")
	
	file_path = input('Enter path to file')
	password = input('Enter password') 

	return user_choice

'''
initEncryptionScheme()
	* opens the configuration file
	* parses parameters into dictionary
	* prints schema contents to console
'''
def initEncryptionScheme():
	global encryption_scheme
	
	# # TODO uncomment this and use as actual code 
	# with  open('file_path') as document:
	# 	encryption_scheme = json.load(document)
	# 	encryption_scheme['password'] = password 
	#		encryption_scheme['filePath'] = file_path

	# with open('config_file') as config_file:
	# 	encryption_scheme = json.load(config_file)
	
	with open('encrypted_file') as encrypted_file:
		encryption_scheme = json.load(encrypted_file)

		print("initEncryptionScheme() - enc_scheme type: ", type(encryption_scheme))
		print("initEncryptionScheme() - conf file:\n", json.dumps(encryption_scheme, indent=1), end="\n")

'''
createMasterKey()
	* generate a master key w/ PBKDF2 standard
	* differntiate btw/ encryption/decryption based on config values
	* passes the password and count paramete to createKey()
'''
def createMasterKey():
	print("createMasterKey()")
	if encryption_scheme['masterSalt'] == "none":
		print("createMasterKey() - encryption: ")
		master_salt = get_random_bytes(16)
		print("createMasterKey() - encryption - master_salt: ", master_salt)
		human_master_salt = b64encode(master_salt).decode('utf-8')
		encryption_scheme['masterSalt'] = human_master_salt
		print("createMasterKey() - encryption - human_master_salt: ", human_master_salt, end="\n")
	else:
		master_salt = encryption_scheme['masterSalt'].encode()
		print("createMasterKey() - decryption - master_salt: ", master_salt, end="\n")

	password = encryption_scheme['password']
	count = encryption_scheme['count']
	return createKey(password, count, master_salt)

'''
createEncryptionKey(master_key, count=1)
	* derive key w/ single iteration from master key
	* use for encryption
''' 
def createEncryptionKey(master_key, count=1):
	if encryption_scheme['encryptionSalt'] == "none":
		encryption_salt = get_random_bytes(16)
		human_encryption_salt = b64encode(encryption_salt).decode('utf-8')
		encryption_scheme['encryptionSalt'] = human_encryption_salt
		print("Human Encryption Salt: ", human_encryption_salt, end="\n")
	else:
		encryption_salt = encryption_scheme['encryptionSalt']
		print("Decryption Encryption Salt: ", encryption_salt, end="\n")

	return createKey(master_key, count, encryption_salt)

'''
createHmacKey(master_key, count=1)
	* derive key w/ single PBKDF2 iteration from master key
	* use for message authentication
'''
def createHmacKey(master_key, count=1):
	if encryption_scheme['hmacSalt'] == "none":
		hmac_salt = get_random_bytes(16)
		human_hmac_salt = b64encode(hmac_salt).decode('utf-8')
		encryption_scheme['hmacSalt'] = human_hmac_salt
		print("Human HMAC Salt: ", human_hmac_salt, end="\n")
	else:
		hmac_salt = encryption_scheme['hmacSalt']
		print("Decryption HMAC Salt: ", hmac_salt, end="\n")

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
	* iv + ciphertext > to string > to bytes
	* derive HMAC from bytes
	* store HMAC in dictionary
'''
def authenticateMessage(hmac_key):
	h = HMAC.new(hmac_key, digestmod=hash_library[encryption_scheme['hashType']])
	
	string_file_metadata = encryption_scheme['iv'] + encryption_scheme['ciphertext']
	bytes_file_metadata = string_file_metadata.encode()
	h.update(bytes_file_metadata)
	encryption_scheme['HMAC'] = h.hexdigest()

'''
saveEncryptedFile()
'''
def saveEncryptedFile():
	# TODO parse filePath to get file name to label new file
	file_name = "encrypted_file"
	encrypted_file = open(file_name, "wb")
	string_encrypted_file = json.dumps(encryption_scheme)
	bytes_encrypted_file = string_encrypted_file.encode()
	encrypted_file.write(bytes_encrypted_file)	

'''
encryptFile()
	* branch of code execution for file encryption
	* collects password from user
	* calls helper functions
'''
def encryptFile():
	global master_key, encryption_key, hmac_key
	
	initEncryptionScheme() 

	master_key = createMasterKey()
	encryption_key = createEncryptionKey(master_key)
	hmac_key = createHmacKey(master_key)

	print("encryptFile(): ", master_key)
	print("Master Key: ", master_key, end='\n') 
	print("Encryption Key: ", encryption_key, end='\n')
	print("HMAC Key: ", hmac_key, end='\n')

	encryptDocument(encryption_key)
	
	authenticateMessage(hmac_key)

	saveEncryptedFile()

	# print("Encryption Scheme: \n", json.dumps(encryption_scheme, indent=1, skipkeys=True), end="\n") 

'''
authenticate()
	* hmac(authenticate iv + cipher text)
'''
def verifyAuthentication(hmac_key):
	print("OLD MAC HASH:", encryption_scheme['HMAC'])
	print("HMAC_KEY", hmac_key)
	h = HMAC.new(hmac_key, digestmod=hash_library[encryption_scheme['hashType']])

	string_file_metadata = encryption_scheme['iv'] + encryption_scheme['ciphertext']
	bytes_file_metadata = string_file_metadata.encode()

	h.update(bytes_file_metadata)
	# TAG = h.hexdigest()
	# print("NEW MAC HASH:", TAG)
	# print("OLD MAC HASH:", encryption_scheme['HMAC'])

	try:
		h.hexverify(encryption_scheme['HMAC'])
		print("The message '%s' is authentic" % encryption_scheme['HMAC'])
		return True
	except ValueError:
		print("The message or the key is wrong")
		return False

'''
decryptDocument()
'''
def decryptDocument():
	# TODO paramaterize padding to appropriate encryption algorithm
	# TODO paramaterize encryption algorithm 
	global encryption_key
	bytes_file_contents_pad = b64decode(encryption_scheme['ciphertext'])
	iv = b64decode(encryption_scheme['iv'])
	print(encryption_key)
	cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
	pt = unpad(cipher.decrypt(bytes_file_contents_pad), AES.block_size)
	print(pt)

	# bytes_plaintext = cipher.decrypt(unpad(bytes_file_contents_pad, standard_key_length[encryption_scheme['encryptionType']]))
	# human_iv = b64encode(cipher.iv).decode('utf-8')
	# human_ciphertext = b64encode(bytes_ciphertext).decode('utf-8')
	
	# encryption_scheme['plaintext'] = human_iv
	
	
'''
decryptFile()
	* determine file path and name from config
	* extract salts
	* derive keys
	* extract iv and ciphertext
	* derive HMAC and compare w/ one provide
	* decrypt
'''
def decryptFile():
	initEncryptionScheme()

	master_key = createMasterKey()
	print("Master Key", master_key)

	encryption_key = createEncryptionKey(master_key)
	print("Encryption Key", encryption_key)

	hmac_key = createHmacKey(master_key)
	print("HMAC Key", hmac_key)

	isVerified = verifyAuthentication(hmac_key)
	print("hashes match: ", isVerified)

	if isVerified == False:
		exit()

	decryptDocument()
	

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
# hash_library = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_key_length = {"3DES": 8, "AES128": 16, "AES256": 32}

'''
variables tracking encryption session and preferences
'''
master_key = b''
encryption_key = b''
hmac_key = b''
encryption_scheme = {}
user_choice = ""
file_path = ""
password = ""

'''
main()-ish
	* Collect info from configuration file
	* Create master key
'''
# user_choice = greeting()
# if user_choice == 1:
	# encryptFile()
# else:
	# decryptFile()

# encryptFile()
decryptFile()

# print("Password: ", password)
# print("File Path: ", file_path)
# print("User Choice: ", user_choice)







