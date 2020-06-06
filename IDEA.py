import random
import numpy

KEY_SIZE = 32
BLOCK_SIZE = 4
SUB_KEYS = 6
SHIFT_BITS = 6
ROUNDS = 5  # Round up the number, NO HALVES


class IDEA:
    def __init__(self, key):
        self.key = random.getrandbits(KEY_SIZE)
        self.rol = lambda val, r_bits, max_bits: \
            (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
            ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
        self.sub_keys = self.key_scheduler()

    def key_scheduler(self):  # Prepares all sub keys for the rounds
        key_scheduler = IDEA_Key_Scheduler(self.key)
        return key_scheduler.prepare_key_schedule()

    def generate_next_key(self):
        self.key = self.rol(self.key, 25, KEY_SIZE)  # Generate new 128 bit key by shifting 25 bits left

    def get_sub_keys(self):
        key_string = str(bin(self.key))[2:]
        for index in range(0, len(key_string), 16):
            self.sub_keys.append(key_string[index: index + 16])  # Divide key into 8 sub keys

        self.next_sub_keys = self.sub_keys[6:8]
        self.generate_next_key()
        temp = []
        key_string = str(bin(self.key))[2:]
        for index in range(0, len(key_string), 16):
            temp.append(key_string[index: index + 16])  # Divide key into 8 sub keys

        for elem in temp[2:8]:
            self.next_sub_keys.append(elem)

        return self.sub_keys[:6]  # Returns list of sub keys


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
            self.key_int = self.shift(self.key_int, SHIFT_BITS, BLOCK_SIZE * 8)  # Make new shifted key
            key_bin_list = get_key_bin_list(self.key_int)
            to_remove = SUB_KEYS - len(new_sub_key) if SUB_KEYS - len(new_sub_key) >= 0 else 0
            [new_sub_key.append(x) for x in key_bin_list[:to_remove]]
            self.sub_keys_list.append(new_sub_key[:SUB_KEYS])

        self.sub_keys_list[-1] = self.sub_keys_list[-1][0:SUB_KEYS - 2]
        return self.sub_keys_list


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


cryptor = IDEA(3698278233)

# key_int = 3698278233  # ["1101", "1100", "0110", "1111", "0011", "1111", "0101", "1001"]
# sched = IDEA_Key_Scheduler(key_int)
[print("Key: " + str(x)) for x in cryptor.sub_keys]
