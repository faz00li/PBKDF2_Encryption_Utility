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

decryption_scheme = {}
with open('encrypted file') as encrypted_file:
  decryption_scheme = json.load(encrypted_file)


print(decryption_scheme)