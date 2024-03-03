from AES import AES_encrypt
from AES import AES_decrypt
from AES import expand_key
# from AES import AES_decrypt 
# from Crypto.Random import get_random_bytes

# AES key
key = 'kwnfy4ncketndjiltjebbgkechtkvhjk'
# expanded = expand_key(key)
# print(len(expanded))
# print(len(key))
plaintext = "Speed I am speed, faster than fast quicker than quick. LIGHTNING LIGHTNING LIGHTNING"

cyphertext = AES_encrypt(plaintext, key, 256)

steve = AES_decrypt(cyphertext, key, 256)

print(f"Plaintext: {plaintext}")
print(f"Cyphertext: {cyphertext}")
print(steve)


# decrypted_plaintext = AES_decrypt(cyphertext, key, 256)
