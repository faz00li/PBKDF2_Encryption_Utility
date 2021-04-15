import json

from Crypto.Protocol.KDF import PBKDF2
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512

from Crypto.Random import get_random_bytes


def initializeParams():
	with open('config_file') as config_file:
		global config_scheme
		config_scheme = json.load(config_file)
	# trouble shooting
	print(\
		"File Path: \t\t" + config_scheme["filePath"],\
		"Hash Type: \t\t" + config_scheme["hashType"],\
		"Encryption Standard: \t" + config_scheme["encryptionType"],\
		"Password: \t\t" + config_scheme["password"],\
		"Iterations: \t\t" + str(config_scheme["count"]),\
		sep='\n')

def createMasterKey():
	hashes = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
	salt = get_random_bytes(16)
	password = config_scheme['password']
	hash_type = hashes[config_scheme['hashType']]
	key = PBKDF2(password, salt, 256, count=1000, hmac_hash_module=hash_type)
	return key

def createKey():
	# TODO: verify key lengths
	standard_key_length = {"3DES": 64, "AES128": 128, "AES256": 256}
	desired_length = standard_key_length[config_scheme["encryptionType"]]
	print("Key Length", desired_length)

	hashes = {"SHA256": Crypto.Hash.SHA256, "SHA512": Crypto.Hash.SHA512}
	salt = get_random_bytes(16)
	password = config_scheme['password']
	hash_type = hashes[config_scheme['hashType']]
	key = PBKDF2(password, salt, desired_length, count=1000, hmac_hash_module=hash_type)
	return key

config_scheme = {}
master_key = b''

initializeParams()
master_key = createMasterKey()

print("Master Key: ", master_key)

encryption_key = createKey()

print("Encryption Key:", encryption_key)







