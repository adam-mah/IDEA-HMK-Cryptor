__author__ = "Adam Mahameed"
__copyright__ = "2020 HMK-IDEA-Cryptor"
__credits__ = ["Adam Mahameed"]
__license__ = "MIT"
__email__ = "adam.mah315@gmail.com"

import binascii

from pckgIDEA.IDEA_bytestream import IDEA

KEY = int('006400c8012c019001f4025802bc0320', 16)
cryptor = IDEA(KEY)  # Initialize cryptor with 128bit key

########ENCRYPTION########
in_file = open("files/song.mp3", "rb")
out_file = open("files/encrypted.mp3", "w", encoding="utf-8")

bytes8 = in_file.read(8)

while bytes8:
    res = cryptor.encrypt(str(binascii.b2a_hex(bytes8))[2:-1], is_hex=True)
    print('Text: ' + str(bytes8.decode('latin-1')) + ' \ Encrypted: ' + res)
    out_file.write(res)
    bytes8 = in_file.read(8)
    #bytes8 = bytes8

in_file.close()
out_file.close()

########DECRYPTION########

in_file = open("files/encrypted.mp3", "r", encoding="utf-8")
out_file = open("files/decrypted.mp3", "wb")

bytes8 = in_file.read(16)
while bytes8:
    res = cryptor.decrypt(bytes8)
    print('Decrypted: ' + str(res))
    out_file.write(res)
    bytes8 = in_file.read(16)

in_file.close()
out_file.close()