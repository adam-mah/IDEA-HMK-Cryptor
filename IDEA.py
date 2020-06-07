import random
import numpy as np
import binascii

KEY_SIZE = 32
BLOCK_SIZE = 4  # Plaintext = 64bits
SUB_KEYS = 6
SHIFT_BITS = 6
ROUNDS = 5  # Round up the number, NO HALVES


class IDEA:
    def __init__(self):
        self.key = 3698278233  # random.getrandbits(KEY_SIZE)
        self.sub_keys = self.key_scheduler()

        self.mul = lambda x, y: np.mod(x * y, 2**4 + 1)
        self.add = lambda x, y: np.mod(x + y, 2**4)
        self.xor = lambda x, y: x ^ y

    def key_scheduler(self):  # Prepares all sub keys for the rounds
        key_scheduler = IDEA_Key_Scheduler(self.key)
        return key_scheduler.prepare_key_schedule()

    def encrypt(self, plain_text):
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
        :param plain_text:
        :return:
        """

        #THIS TEST SAMPLE OUTPUT MUST MATCH https://www.geeksforgeeks.org/simplified-international-data-encryption-algorithm-idea/ output

        X = get_pt_bin_block_list(plain_text)
        X = ["00001001", "00001100", "00001010", "00001100"]
        K = self.sub_keys
        print("Plaintext binary:" + str(X))

        [print("Key: " + str(x)) for x in K]

        step = ['0'] * 14
        for i in range(0, ROUNDS - 1):
            print("Round " + str(i + 1) + " input " + str(X))
            print("Round " + str(i + 1) + " input key" + str(K[i]))
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
            #for y in range(14):
            #    print("Step "+str(y+1)+": "+str(bin(int(step[y])))[2:])

            X = [str(bin(int(step[10])))[2:], str(bin(int(step[12])))[2:], str(bin(int(step[11])))[2:],
                 str(bin(int(step[13])))[2:]]  # Swap step 12 and 13

            for j in range(0, len(X)):
                X[j] = '0' * (4 - len(X[j])) + X[j]

            print("Round " + str(i + 1) + " output " + str(X)+"\n---------------")

        """X1 * K1
           X2 + K2
           X3 + K3
           X4 * K4"""
        X = [str(bin(int(step[10])))[2:], str(bin(int(step[11])))[2:], str(bin(int(step[12])))[2:],
             str(bin(int(step[13])))[2:]]
        result = []
        result.append(self.mul(int(X[0], 2), int(K[ROUNDS - 1][0], 2)))
        result.append(self.add(int(X[1], 2), int(K[ROUNDS - 1][1], 2)))
        result.append(self.add(int(X[2], 2), int(K[ROUNDS - 1][2], 2)))
        result.append(self.mul(int(X[3], 2), int(K[ROUNDS - 1][3], 2)))
        print(result)


""" PSEUDO for Key-Scheduler
Key1 1101 1100 0110 1111 0011 1111 0101 1001
Shifted Key1 0001 1011 1100 1111 1101 0110 0111 0111
Shifted Key2 1111 0011 1111 0101 1001 1101 1100 0110
Shifted Key3 1111 1101 0110 0111 0111 0001 1011 1100

Sub 1 1101 1100 0110 1111 0011 1111
Sub 2 0101 1001 0001 1011 1100 1111
Sub 3 1101 0110 0111 0111 1111 0011
Sub 4 1111 0101 1001 1101 1100 0110
Sub 5 1111 1101 0110 0111 0111 0001

0. main-sub-key = main key
1. Take 6 as sub-key from original key 
2. put the remaining into new-sub-key2 (Up to 6 Max)
3. Shift main key = new key
4. Take 6-len(new key) from shifted key and add to the end of new-sub-key2
5. repeat from 2

By Fucking Adam
"""
class IDEA_Key_Scheduler:
    def __init__(self, key_int):
        self.key_int = key_int
        self.sub_keys_list = []
        self.shift = lambda val, r_bits, max_bits: \
            (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
            ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

    def prepare_key_schedule(self):
        key_bin_list = get_key_bin_list(self.key_int)
        self.sub_keys_list.append(key_bin_list[:SUB_KEYS])

        to_remove = SUB_KEYS
        for i in range(0, ROUNDS - 1):
            temp = key_bin_list
            del temp[:to_remove]
            new_sub_key = temp
            self.key_int = self.shift(self.key_int, SHIFT_BITS, KEY_SIZE)  # Make new shifted key
            key_bin_list = get_key_bin_list(self.key_int)
            to_remove = SUB_KEYS - len(new_sub_key) if SUB_KEYS - len(new_sub_key) >= 0 else 0
            [new_sub_key.append(x) for x in key_bin_list[:to_remove]]
            self.sub_keys_list.append(new_sub_key[:SUB_KEYS])

        self.sub_keys_list[-1] = self.sub_keys_list[-1][0:SUB_KEYS - 2]
        return self.sub_keys_list


def get_pt_bin_block_list(plain_text):  # 4 Blocks 16 bit each
    pt_block_list = []

    temp = ' '.join(item[2:] for item in map(bin, plain_text.encode('ascii')))  # Binary plain text string

    temp_list = []
    for index in range(0, len(temp), 8):
        temp_list.append(temp[index: index + 8])  # Divide plain text into bytes
    for i in range(len(temp_list)):
        temp_list[i] = temp_list[i].replace(" ", "")  # Remove white spaces from bytes
        temp_list[i] = ''.join(['0' * (8 - len(temp_list[i])) if len(temp_list[i]) < 8 else '']) + temp_list[i]  # Add
        # missing zeros for prefix to binary key string making each char 8 bits

    for i in range(8 - len(temp_list)):  # Expand list to 8 bytes(64bits)
        temp_list.insert(0, '0' * 8)
    ########################
    for i in range(0, len(temp_list), 2):  # Combine every 2 bytes to form 16 bits blocks
        pt_block_list.append(''.join([s for s in temp_list[i:i + 2]]))

    return pt_block_list


def get_key_bin_list(key_int):
    """
    Convert INT to binary string of key size
    KEY_SIZE = BLOCK_SIZE * 8(num of keys)
    :param key_int: Key in INT format
    :return: Binary key list divided to 8 bytes
    """
    key_bin = str(bin(key_int))[2:]
    key_bin = ''.join(['0' for i in range(0, BLOCK_SIZE * 8 - len(key_bin)) if
                       len(key_bin) < BLOCK_SIZE * 8]) + key_bin  # Add missing zeros for prefix to binary key string

    key_bin_list = []
    for index in range(0, len(key_bin), BLOCK_SIZE):
        key_bin_list.append(key_bin[index: index + BLOCK_SIZE])  # Divide key into 8 sub keys

    return key_bin_list


cryptor = IDEA()
# get_pt_bin_block_list('adam1234')
# key_int = 3698278233  # ["1101", "1100", "0110", "1111", "0011", "1111", "0101", "1001"]
# sched = IDEA_Key_Scheduler(key_int)
cryptor.encrypt('adam')
