from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.Random import get_random_bytes
import json

key = get_random_bytes(16)  # AES-128
iv = get_random_bytes(16)   # Initialization vector

cipher = AES.new(key, AES.MODE_CBC, iv)

plaintext = b'This is plaintext'

decipher = AES.new(key, AES.MODE_CBC, iv)

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
print("Ciphertext:", ciphertext)


decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Decrypted:", decrypted)


