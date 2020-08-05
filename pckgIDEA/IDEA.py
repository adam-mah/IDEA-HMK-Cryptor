__author__ = "Adam Mahameed, Karam Abu Mokh"
__copyright__ = "2020 HMK-IDEA-Cryptor"
__credits__ = ["Adam Mahameed", "Karam Abu Mokh"]
__license__ = "MIT"
__email__ = "adam.mah315@gmail.com"
import secrets

from pckgIDEA.IDEA_Key_Scheduler import IDEA_Key_Scheduler

KEY_SIZE = 128
BLOCK_SIZE = 16  # Plaintext = 64bits
SUB_KEYS = 6
SHIFT_BITS = 25
ROUNDS = 9  # Round up the number, NO HALVES


class IDEA:
    def __init__(self, key=secrets.randbits(128), log=False):
        self.key = key
        self.scheduler = IDEA_Key_Scheduler(self.key)
        self.enc_sub_keys, self.dec_sub_keys = self.schedule_keys()
        self.log = log
        self.mul = lambda x, y: (x * y) % (2 ** BLOCK_SIZE + 1)  # int(np.mod(x * y, 2 ** BLOCK_SIZE + 1))
        self.add = lambda x, y: (x + y) % (2 ** BLOCK_SIZE)  # int(np.mod(x + y, 2 ** BLOCK_SIZE))
        self.xor = lambda x, y: x ^ y

    def schedule_keys(self):  # Prepares all sub keys for the rounds
        return self.scheduler.encryption_key_schedule(), self.scheduler.decryption_key_schedule()

    def calculate_cipher(self, sub_keys, text):
        """
                X1 * K1
                X2 + K2
                X3 + K3
                X4 * K4
                Step 1 ^ Step 3
                Step 2 ^ Step 4
                Step 5 * K5
                Step 6 + Step 7
                Step 8 * K6
                Step 7 + Step 9
                Step 1 ^ Step 9
                Step 3 ^ Step 9
                Step 2 ^ Step 10
                Step 4 ^ Step 10
                :param text: Cipher/Plain 4 16-bit blocks
                :param sub_keys: Decryption/Encryption Sub Keys [A list of 9 lists, 6 subkeys for each round,
                                    4 subkeys for the last round]
                :return: ciphered/deciphered text
                """
        X = text
        K = sub_keys

        step = ['0'] * 14
        for i in range(0, ROUNDS - 1):
            step[0] = (self.mul(X[0], int(K[i][0], 2)))
            step[1] = (self.add(X[1], int(K[i][1], 2)))
            step[2] = (self.add(X[2], int(K[i][2], 2)))
            step[3] = (self.mul(X[3], int(K[i][3], 2)))
            step[4] = (self.xor(step[0], step[2]))
            step[5] = (self.xor(step[1], step[3]))
            step[6] = (self.mul(step[4], int(K[i][4], 2)))
            step[7] = (self.add(step[5], step[6]))
            step[8] = (self.mul(step[7], int(K[i][5], 2)))
            step[9] = (self.add(step[6], step[8]))
            step[10] = (self.xor(step[0], step[8]))
            step[11] = (self.xor(step[2], step[8]))
            step[12] = (self.xor(step[1], step[9]))
            step[13] = (self.xor(step[3], step[9]))
            # [print("Step "+str(y)+": "+str(hex(int(step[y]))) + "({0})".format(int(step[y]))) for y in range(14)]

            if self.log:
                print("Round [" + str(i + 1) + "] HEX input   " + ' '.join([str(hex(int(x))) for x in X]))
                print("Round [" + str(i + 1) + "] HEX sub-key " + ' '.join([str(hex(int(k, 2))) for k in K[i]]))
            X = [step[10], step[11], step[12], step[13]]  # Swap step 12 and 13
            if self.log:
                print("Round [" + str(i + 1) + "] HEX output  " + ' '.join(
                    [str(hex(int(x))) for x in X]) + "\n---------------")

        """X1 * K1
           X2 + K2
           X3 + K3
           X4 * K4"""
        X = [step[10], step[12], step[11], step[13]]
        result = [self.mul(X[0], int(K[ROUNDS - 1][0], 2)), self.add(X[1], int(K[ROUNDS - 1][1], 2)),
                  self.add(X[2], int(K[ROUNDS - 1][2], 2)), self.mul(X[3], int(K[ROUNDS - 1][3], 2))]

        temp = [str(hex(int(x)))[2:] for x in result]
        temp = ['0' * (4 - len(x)) + x for x in temp]
        cipher = ''.join([x for x in temp])

        if self.log:
            print("Round [" + str(ROUNDS - 0.5) + "] HEX input   " + ' '.join([str(hex(int(x))) for x in X]))
            print("Round [" + str(ROUNDS - 0.5) + "] HEX sub-key " + ' '.join(
                [str(hex(int(k, 2))) for k in K[ROUNDS - 1]]))
            print("Round [" + str(ROUNDS - 0.5) + "] HEX output  " + ' '.join([str(hex(int(x))) for x in result])
                  + "\n---------------")
            print("Final Cipher/Decipher: " + cipher + "\n---------------")

        return cipher  # Hex string

    def encrypt(self, plain_text=''):
        if self.log:
            print("-------ENCRYPTING [" + plain_text + "]-------")
        plain_text = get_pt_block(plain_text)
        return self.calculate_cipher(self.enc_sub_keys, plain_text)

    def decrypt(self, cipher_text=''):
        if self.log:
            print("-------DECRYPTING [" + cipher_text + "]-------")
        cipher_text = get_cipher_block(cipher_text)
        res = self.calculate_cipher(self.dec_sub_keys, cipher_text)
        res = ''.join('0' * (16 - len(res))) + res
        return ''.join([chr(int(''.join(c), 16)) for c in zip(res[0::2], res[1::2])])


def get_pt_block(plain_text):  # 4 Blocks 16 bit each
    """
    Divide plain text to binary and extend each char to 8 bits making a 64-bit long binary string
    and divide the string to 4 blocks each one contains 16-bit binary digits
    :param plain_text: Plain text of maximum 8 chars
    :return: Plain text combined binaries(16-bit) divided into a list of 4 blocks (converted to int)
    """
    pt_block = []
    temp = ' '.join(bin(ord(item))[2:] for item in plain_text)
    temp = temp.split(' ')  # Split chars into list of 8 cells
    temp_list = ['0' * (8 - len(item)) + item for item in temp]
    temp = ''.join(byte for byte in temp_list)
    temp = ''.join('0' * (BLOCK_SIZE * 4 - len(temp))) + temp
    [pt_block.append(int(temp[i:i + 16], 2)) for i in range(0, len(temp), 16)]
    return pt_block


def get_cipher_block(cipher_text):  # 4 Blocks 16 bit each
    """
    Divide cipher 16-hex digits into a list of 4 blocks(4 hex digits each)
    :param cipher_text: Ciphered text (16-Hex Digits)
    :return: Cipher text divided into a list of 4 blocks (converted to int)
    """
    cipher_block = []
    [cipher_block.append(int(cipher_text[i:i + 4], 16)) for i in range(0, len(cipher_text), 4)]
    return cipher_block


if __name__ == "__main__":
    KEY = int('006400c8012c019001f4025802bc0320', 16)
    plain_text = 'ADAM'
    cryptor = IDEA()  # Initialize cryptor with 128bit key
    cipher_text = cryptor.encrypt(plain_text)
    print(''.join([chr(int(''.join(c), 16)) for c in zip(cipher_text[0::2], cipher_text[1::2])]))
    deciphered_text = cryptor.decrypt(cipher_text)
    print("Original text = {0}\nEncryption key = {3}\nCiphered text = {1}\nDeciphered text = {2}".format(plain_text,
                                                                                                         cipher_text,
                                                                                                         deciphered_text,
                                                                                                         cryptor.key))