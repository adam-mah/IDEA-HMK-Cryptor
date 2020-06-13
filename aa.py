from pckgIDEA.IDEA import IDEA
from HMKnapsack import *
from DSA import DSA
import binascii
KEY = int('006400c8012c019001f4025802bc0320', 16)
plain_text = 'aDAM'

# IDEA Example
cryptor = IDEA(KEY)  # Initialize cryptor with 128bit key

in_file = open("song.mp3", "rb")
out_file = open("encrypted.mp3", "w")
log_file = open("enc log_file.txt", "w")

bytes8 = in_file.read(8)
print(bytes8.decode())
bytes8 = binascii.b2a_hex(bytes8)#Convert bytes to Hex
print(bytes8)

while bytes8:
    pass
    # Do stuff with byte.
    #res = cryptor.encrypt(str(binascii.b2a_hex(bytes8))[2:-1],enc=hex)
    #log_file.write(res)
    #out_file.write(res.encode("utf-8"))
    #print(bytes8.decode())
    bytes8 = binascii.b2a_hex(bytes8)  # Convert bytes to Hex
    print(bytes8)
    #bytes8 = in_file.read(8)
    #print(bytes8)
    #print(str(binascii.b2a_hex(bytes8))[2:-1])
    #print(bytes.fromhex(str(binascii.b2a_hex(bytes8))[2:-1]))


in_file.close()
out_file.close()
log_file.close()
"""in_file = open("encrypted.mp3", "rb")
out_file = open("decrypted.mp3", "wb")

bytes8 = in_file.read(16)
print(bytes8.decode("utf-8"))
print(bytes.fromhex(bytes.decode(bytes8)))
#byte3 = binascii.b2a_hex(bytes8)#Convert bytes to Hex
#print(byte3.decode())
#print(bytes.fromhex(str(byte3)[2:-1]))#
while bytes8:
    # Do stuff with byte.
    bytes8 = in_file.read(16)
    print(bytes8.decode("utf-8"))
    res = cryptor.decrypt(str(bytes8.decode("utf-8")))
    #print(binascii.b2a_hex(res).encode())
    #print(res.encode())
    if len(res)<16:
        res = ''.join('0' * (16-len(res)))+res
    out_file.write(bytes.fromhex(res[:16]))
    #print("encrypted:" + str(bytes8.decode()))
    #cryptor.decrypt(str(bytes8.decode()))
    #bytes_hex = binascii.b2a_hex(bytes8.decode())
    #out_file.write(binascii.a2b_hex(cryptor.decrypt(str(bytes_hex))))"""

"""in_file = open("orig.txt", "r")
out_file = open("enc.txt", "w")

bytes8 = in_file.read(8)
while bytes8:
    # Do stuff with byte.
    print(bytes8)
    out_file.write(cryptor.encrypt(bytes8))
    bytes8 = in_file.read(8)

in_file.close()
out_file.close()"""

"""in_file = open("enc.txt", "r")
out_file = open("dec.txt", "w")
print("\nDecryption file\n")
bytes8 = in_file.read(16)
while bytes8:
    # Do stuff with byte.
    out_file.write(cryptor.decrypt(bytes8))
    bytes8 = in_file.read(16)

in_file.close()
out_file.close()"""
