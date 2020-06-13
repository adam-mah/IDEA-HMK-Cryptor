import binascii
import random
import numpy as np
from pckgIDEA.IDEA_Key_Scheduler import IDEA_Key_Scheduler

KEY_SIZE = 128
BLOCK_SIZE = 16  # Plaintext = 64bits
SUB_KEYS = 6
SHIFT_BITS = 25
ROUNDS = 9  # Round up the number, NO HALVES


class IDEA:
    def __init__(self, key=random.getrandbits(KEY_SIZE)):
        self.key = key  # random.getrandbits(KEY_SIZE)
        self.scheduler = IDEA_Key_Scheduler(self.key)
        self.enc_sub_keys, self.dec_sub_keys = self.schedule_keys()

        self.mul = lambda x, y: int(np.mod(x * y, 2 ** BLOCK_SIZE + 1))
        self.add = lambda x, y: int(np.mod(x + y, 2 ** BLOCK_SIZE))
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
                The input to the next round is Step 11 || Step 13 || Step 12 || Step 14, which becomes X1 || X2 || X3 || X4.
                This swap between 12 and 13 takes place after each complete round, except the last complete round (4th round),
                where the input to the final half round is Step 11 || Step 12 || Step 13 || Step 14.
                :param text: Cipher/Plain binary text
                :param sub_keys: Decryption/Encryption Sub Keys
                :return: ciphered/deciphered text
                """
        # THIS TEST SAMPLE OUTPUT MUST MATCH https://www.geeksforgeeks.org/simplified-international-data-encryption-algorithm-idea/ output
        X = text
        K = sub_keys
        print("Binary text:" + str(X))

        # Print sub keys
        """
        [print("BIN Sub-Key: " + str(x)) for x in K]
        print("------------")
        for lst in K:
            print("HEX Sub-Key: " + ' '.join([str(hex(int(elem, 2)))[2:] for elem in lst]))
        print("------------\n")
        """

        step = ['0'] * 14
        for i in range(0, ROUNDS - 1):
            # Input print
            # print("Round [" + str(i + 1) + "] BIN input " + str(X))
            # print("Round [" + str(i + 1) + "] DEC input " + str([int(x, 2) for x in X]))
            # print("Round [" + str(i + 1) + "] HEX input " + ' '.join([str(hex(int(x, 2)))[2:] for x in X]))
            # Sub Key print
            # print("Round [" + str(i + 1) + "] BIN sub-key " + str(K[i]))
            # print("Round [" + str(i + 1) + "] DEC sub-key " + str([int(k, 2) for k in K[i]]))
            # print("Round [" + str(i + 1) + "] HEX sub-key " + ' '.join([str(hex(int(k, 2)))[2:] for k in K[i]]))
            step[0] = (self.mul(int(X[0], 2), int(K[i][0], 2)))
            step[1] = (self.add(int(X[1], 2), int(K[i][1], 2)))
            step[2] = (self.add(int(X[2], 2), int(K[i][2], 2)))
            step[3] = (self.mul(int(X[3], 2), int(K[i][3], 2)))
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
            # for y in range(14):
            #    print("Step "+str(y)+": "+str(bin(int(step[y])))[2:] + "({0})".format(int(step[y])))

            X = [str(bin(int(step[10])))[2:], str(bin(int(step[11])))[2:], str(bin(int(step[12])))[2:],
                 str(bin(int(step[13])))[2:]]  # Swap step 12 and 13

            for j in range(0, len(X)):
                X[j] = '0' * (4 - len(X[j])) + X[j]

            # print("Round [" + str(i + 1) + "] BIN output " + str(X))
            # print("Round [" + str(i + 1) + "] DEC output " + str([int(x, 2) for x in X]))
        # print("Round [" + str(i + 1) + "] HEX output " + ' '.join([str(hex(int(x, 2)))[2:] for x in X])
        #                  + "\n---------------")

        """X1 * K1
           X2 + K2
           X3 + K3
           X4 * K4"""
        X = [str(bin(int(step[10])))[2:], str(bin(int(step[12])))[2:], str(bin(int(step[11])))[2:],
             str(bin(int(step[13])))[2:]]
        # print("Round [" + str(ROUNDS - 0.5) + "] BIN input " + str(X))
        # print("Round [" + str(ROUNDS - 0.5) + "] DEC input " + str([int(x, 2) for x in X]))
        # print("Round [" + str(ROUNDS - 0.5) + "] HEX input " + ' '.join([str(hex(int(x, 2)))[2:] for x in X]))
        # Sub Key print
        # print("Round [" + str(ROUNDS - 0.5) + "] BIN sub-key " + str(K[i]))
        # print("Round [" + str(ROUNDS - 0.5) + "] DEC sub-key " + str([int(k, 2) for k in K[i]]))
        # print("Round [" + str(ROUNDS - 0.5) + "] HEX sub-key " + ' '.join(
        # [str(hex(int(k, 2)))[2:] for k in K[ROUNDS - 1]]))
        result = []
        result.append(self.mul(int(X[0], 2), int(K[ROUNDS - 1][0], 2)))
        result.append(self.add(int(X[1], 2), int(K[ROUNDS - 1][1], 2)))
        result.append(self.add(int(X[2], 2), int(K[ROUNDS - 1][2], 2)))
        result.append(self.mul(int(X[3], 2), int(K[ROUNDS - 1][3], 2)))

        cipher = ''.join([str(hex(int(x)))[2:] for x in result])
        print("Final Cipher/Decipher: " + cipher + "\n---------------")

        return cipher

    def encrypt(self, plain_text=''):
        plain_text = plain_text.encode().hex()
        plain_text = get_bin_block(plain_text)
        return self.calculate_cipher(self.enc_sub_keys, plain_text)

    def decrypt(self, cipher_text=''):
        cipher_text = get_bin_block(cipher_text)
        return bytes.fromhex(self.calculate_cipher(self.dec_sub_keys, cipher_text)).decode()


def get_bin_block(plain_text):  # 4 Blocks 16 bit each
    plain_text = str(bin(int(plain_text, 16))[2:])
    print(plain_text)
    plain_text = ''.join(['0' for l in range(64 - len(plain_text))]) + plain_text
    temp_list = []
    for index in range(0, len(plain_text), 16):
        temp_list.append(plain_text[index: index + 16])  # Divide plain text into bytes
    plain_text = temp_list
    return plain_text


if __name__ == "__main__":
    KEY = int('006400c8012c019001f4025802bc0320', 16)
    plain_text = 'a6b23421'
    cryptor = IDEA()  # Initialize cryptor with 128bit key
    cipher_text = cryptor.encrypt(plain_text)
    deciphered_text = cryptor.decrypt(cipher_text)
    print(
        "Original text = {0}\nCiphered text = {1}\nDeciphered text = {2}".format(plain_text, cipher_text,
                                                                                 deciphered_text))

"""setKey(006400c8012c019001f4025802bc0320)
encryptIDEA(05320a6414c819fa)
  Round 1	X = 0532 0a64 14c8 19fa ; SK = 0064 00c8 012c 0190 01f4 0258 
  Round 2	X = 0746 1534 0c68 913c ; SK = 02bc 0320 9002 5803 2003 e804 
  Round 3	X = f1b7 8e88 78e2 4170 ; SK = b005 7806 4000 c801 0640 07d0 
  Round 4	X = ec90 b610 aa33 22ec ; SK = 0960 0af0 0c80 0190 0320 04b0 
  Round 5	X = e262 e986 4690 171a ; SK = a012 c015 e019 0003 2006 4009 
  Round 6	X = f0d8 4b29 743f 98ea ; SK = 600c 800f 2bc0 3200 0640 0c80 
  Round 7	X = 22a1 529b fe1f a304 ; SK = 12c0 1900 1f40 2580 000c 8019 
  Round 8	X = a151 f439 81d9 1462 ; SK = 0025 8032 003e 804b 0057 8064 
  Output	X = ecda 3ce7 3e53 a60c ; SK = 3200 4b00 6400 7d00 0000 0000 
  = 65be87e7a2538aed"""
