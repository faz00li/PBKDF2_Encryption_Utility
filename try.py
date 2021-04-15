from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

password = b'my super secret'
salt = get_random_bytes(16)
keys = PBKDF2(password, salt, dkLen=64, count=4096, prf=SHA256)

key1 = keys[:16]
print(keys)
# print(keys.decode('ascii'))

cipher = AES.new(key,aes.MODE_CBC,)


# AES-128 -> 16
# AES-256 -> 32