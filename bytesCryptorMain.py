import binascii

from pckgIDEA.IDEA_bytestream import IDEA

KEY = int('006400c8012c019001f4025802bc0320', 16)

# IDEA Example
cryptor = IDEA(KEY)  # Initialize cryptor with 128bit key
in_file = open("files/song.mp3", "rb")
out_file = open("files/encrypted.mp3", "w", encoding="utf-8")

bytes8 = in_file.read(8)
print(bytes8.decode('latin-1'))
# bytes8 = binascii.b2a_hex(bytes8)#Convert bytes to Hex
print(bytes8)
# print(bytes.fromhex(str(bytes8)[2:-1]))
print(binascii.b2a_hex(bytes8))

while bytes8:
    res = cryptor.encrypt(str(binascii.b2a_hex(bytes8.decode('latin-1')))[2:-1], is_hex=True)
    print('Enc: ' + res)
    out_file.write(res)
    bytes8 = in_file.read(8)
    #bytes8 = bytes8

in_file.close()
out_file.close()
in_file = open("files/encrypted.mp3", "r", encoding="utf-8")
out_file = open("files/decrypted.mp3", "w", encoding="latin-1")

bytes8 = in_file.read(16)
# byte3 = binascii.b2a_hex(bytes8)#Convert bytes to Hex
# print(byte3.decode())
# print(bytes.fromhex(str(byte3)[2:-1]))#
while bytes8:
    # Do stuff with byte.
    res = cryptor.decrypt(bytes8, codec='latin-1')
    print('Dec: ' + res)
    # if len(res)<16:
    #    res = ''.join('0' * (16-len(res)))+res
    out_file.write(res)
    bytes8 = in_file.read(16)
    # print("encrypted:" + str(bytes8.decode()))
    # cryptor.decrypt(str(bytes8.decode()))
    # bytes_hex = binascii.b2a_hex(bytes8.decode())
    # out_file.write(binascii.a2b_hex(cryptor.decrypt(str(bytes_hex))))

in_file.close()
out_file.close()