from pckgIDEA.IDEA import IDEA
from HMKnapsack import *
from DSA import DSA

KEY = int('006400c8012c019001f4025802bc0320', 16)
plain_text = 'aDAM'

# IDEA Example
cryptor = IDEA(KEY)  # Initialize cryptor with 128bit key
cipher_text = cryptor.encrypt(plain_text)
deciphered_text = cryptor.decrypt(cipher_text)
print(
    "Original text = {0}\nCiphered text = {1}\nDeciphered text = {2}".format(plain_text, cipher_text, deciphered_text))

# HM-Knapsack Example
print("\n\n---------HM-Knapsack---------")
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
print("Encrypted message: {0} \nDecrypted message: {1}".format(cipher_text, decrypted_cipher_text))

# DSA
print("\n\n---------DSA---------")
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
    print("Result: Verification failed!")