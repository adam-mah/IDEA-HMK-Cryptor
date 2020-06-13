from pckgIDEA.IDEA import IDEA
from HMKnapsack import *
from DSA import DSA
import binascii

# Secure transmission of songs files.
# Creation of a secure chanal with  Merkle–Hellman knapsack + Key transmision and identication.
# Recieveing of an engypted song file and checking of its validity.
# Encrytion-decryption by algorithm IDEA

"""KEY = int('006400c8012c019001f4025802bc0320', 16)
plain_text = 'aDAM'

# IDEA Example
cryptor = IDEA(KEY)  # Initialize cryptor with 128bit key
cipher_text = cryptor.encrypt(plain_text)
deciphered_text = cryptor.decrypt(cipher_text)
print(
    "Original text = {0}\nCiphered text = {1}\nDeciphered text = {2}".format(plain_text, cipher_text, deciphered_text))"""

# HM-Knapsack Example
"""print("\n\n---------HM-Knapsack---------")
MAX_CHARS = 128
while True:
    plain_text = 'zBRA'#input("Insert a message to encrypt: ")
    if len(plain_text) <= MAX_CHARS:
        break
    else:
        print("Input must be shorter than 128chars")
w, q, r = generate_keys(len(plain_text))  # Generate encryption keys
b = generate_public_key(w, q, r)  # Public Key

cipher_text = hmk_encrypt(plain_text, b)  # Encrypted plain text
decrypted_cipher_text = hmk_decrypt(cipher_text, w, q, r)  # Decrypted cipher
print("w: {0}\nq: {1}\nr: {2}".format(w, q, r))
print("Encrypted message: {0} \nDecrypted message: {1}".format(cipher_text, decrypted_cipher_text))"""

# DSA
"""print("\n\n---------DSA---------")
signer = DSA()
M = "zbraaa"  # str.encode(text, "ascii")
r, s = signer.sign(M)
p, q, g, pkey = signer.get_keys()
# print(M, r, s, p, q, g, y, x, sep='\n')

print("Message: {0}\nSignature pair:\nr sign: {1}\ns sign: {2}\nKey values:\np: {3}\nq: {4}\ng: {5}\n"
      "Public key y: {6}".format(M, r, s, p, q, g, pkey))
if DSA.verify(M, r, s, p, q, g, pkey):
    print('Result: Verified!')
else:
    print("Result: Verification failed!")"""

################
KEY_SIZE = 128


##Generate IDEA Key and encrypt it with HMK
# Transmit HMK cipher along with its w , q ,r values to the receiver side + signature
# Encrypt data (every 8 bytes , total of 64bits) with
def sign_message(M):
    r, s = cipher_sign.sign(M)
    p, q, g, pkey = cipher_sign.get_keys()
    return (r, s, p, q, g, pkey)


# RECEIVER SIDE
print("\n------RECEIVER SIDE------\n")
print("Generating private and public keys...")
HMw, HMq, HMr = generate_keys(KEY_SIZE)  # Generate encryption keys
print("w: {0}\nq: {1}\nr: {2}".format(HMw, HMq, HMr))
HMb = generate_public_key(HMw, HMq, HMr)  # Public Key
print("Sending {0}...] public key to sender...".format(str(HMb)[:10]))
##NOW PUBLISH HWb and SEND A MESSAGE TO THE SENDER TO ENCRYPT


##SENDER SIDE
print("\n------SENDER SIDE------\n")
# Receives public key and encrypts IDEA key accordingly and sends back to receiver
print("Receiving public key {0} from receiver...".format(str(HMb)[:10]))
KEY = int('006400c8012c019001f4025802bc0320', 16)
id_cryptor = IDEA(KEY)
cipher_text = hmk_encrypt(str(id_cryptor.key), HMb)  # Encrypted plain text
# print("w: {0}\nq: {1}\nr: {2}".format(HMw, HMq, HMr))
print("Encrypting IDEA key using HMKnapsack receiver public key")
print(
    " Original message: {0}\nEncrypted message: {1}".format(str(id_cryptor.key), cipher_text))

"""Sign encryption"""
cipher_sign = DSA()
M = cipher_text
sign_keys = sign_message(M)
print("Message signed!")



##RECEIVER SIDE
print("\n------RECEIVER SIDE------\n")
print("Encrypted IDEA key received.")
if DSA.verify(M, sign_keys[0], sign_keys[1], sign_keys[2], sign_keys[3], sign_keys[4], sign_keys[5]):
    print('Signature Verified!')
else:
    print("Sinature Verification failed!")

decrypted_cipher_text = hmk_decrypt(cipher_text, HMw, HMq, HMr)  # Decrypted cipher
print("Decrypting IDEA key with HMKnapsack private keys")
print(
    "Encrypted message: {0} \nDecrypted message: {1}".format(cipher_text, decrypted_cipher_text))
