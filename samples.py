import sympy

from Cryptors.HMKnapsack import HMKnapsack
from pckgIDEA.IDEA import IDEA
from Cryptors.DSA import DSA
import Crypto.Util.number as num

# Secure transmission of songs files.
# Creation of a secure chanal with  Merkle–Hellman knapsack + Key transmision and identication.
# Recieveing of an engypted song file and checking of its validity.
# Encrytion-decryption by algorithm IDEA
print(num.getPrime(128))
print("\n\n---------IDEA---------")
KEY = int('006400c8012c019001f4025802bc0320', 16)
plain_text = 'HiStackO'
# IDEA Example
cryptor = IDEA()  # Initialize cryptor with 128bit key
cipher_text = cryptor.encrypt(plain_text)
deciphered_text = cryptor.decrypt(cipher_text)
print(
    "Original text = {0}\nEncryption key = {3}\nCiphered text = {1}\nDeciphered text = {2}".format(plain_text,
                                                                                                   cipher_text,
                                                                                                   deciphered_text,
                                                                                                   cryptor.key))

# HM-Knapsack Example
print("\n\n---------HM-Knapsack---------")
MAX_CHARS = 128
while True:
    plain_text = 'ThisMessageIsEncrypted'  # input("Insert a message to encrypt: ")
    if len(plain_text) <= MAX_CHARS:
        break
    else:
        print("Input must be shorter than 128chars")
hmkCryptor = HMKnapsack(len(plain_text))
cipher_text = hmkCryptor.encrypt(plain_text, hmkCryptor.get_public_key())
decrypted_cipher_text = hmkCryptor.decrypt(cipher_text)
print("Encrypted message: {0} \nDecrypted message: {1}".format(cipher_text, decrypted_cipher_text))

# DSA
print("\n\n---------DSA---------")
signer = DSA()
M = "MyMessage"  # str.encode(text, "ascii")
r, s = signer.sign(M)
p, q, g, pkey = signer.get_keys()
# print(M, r, s, p, q, g, y, x, sep='\n')

print("Message: {0}\nSignature pair:\nr sign: {1}\ns sign: {2}\nKey values:\np: {3}\nq: {4}\ng: {5}\n"
      "Public key y: {6}".format(M, r, s, p, q, g, pkey))
if DSA.verify(M, r, s, p, q, g, pkey):
    print('Result: Verified!')
else:
    print("Result: Verification failed!")

################
