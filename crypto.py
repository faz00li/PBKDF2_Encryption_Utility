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
	* prints schema contents to console
'''
def initEncryptionScheme():
  with open('config_file') as config_file:
    encryption_scheme = json.load(config_file)
    
    print("initEncryptionScheme")
    print("Encryption Scheme Type: ", type(encryption_scheme))
    print("Config File Contents:\n", json.dumps(encryption_scheme, indent=1), end="\n")

'''
Dictionaries of hash modules and info about encrytion standards
Can be easily updated for purposes of crypto-agility
'''
hash_library = {"SHA256": SHA256, "SHA512": SHA512}
standard_key_length = {"3DES": 8, "AES128": 16, "AES256": 32}

'''
variables tracking encryption session and preferences
'''
encryption_scheme = {}
state = {}
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