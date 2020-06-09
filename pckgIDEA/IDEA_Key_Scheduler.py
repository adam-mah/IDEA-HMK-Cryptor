import sympy

KEY_SIZE = 128
BLOCK_SIZE = 16  # Plaintext = 64bits
SUB_KEYS = 6
SHIFT_BITS = 25
ROUNDS = 9  # Round up the number, NO HALVES

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
By Adam"""


class IDEA_Key_Scheduler:
    def __init__(self, key_int):
        self.key_int = key_int
        self.enc_sub_keys_list = []
        self.dec_sub_keys_list = []
        self.shift = lambda val, r_bits, max_bits: \
            (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
            ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

        self.mulInv = lambda x: sympy.mod_inverse(x, 2 ** BLOCK_SIZE + 1)
        self.addInv = lambda x: (0x10000 - x) & 0xFFFF

    def encryption_key_schedule(self):
        key_bin_list = get_key_bin_list(self.key_int)
        self.enc_sub_keys_list.append(key_bin_list[:SUB_KEYS])

        # print("HEX New Sub key[0]: " + ' '.join([str(hex(int(elem, 2)))[2:] for elem in key_bin_list[:SUB_KEYS]]))
        to_remove = SUB_KEYS
        for i in range(0, ROUNDS - 1):
            temp = key_bin_list
            del temp[:to_remove]
            if to_remove != 0:
                new_sub_key = temp
                to_remove = SUB_KEYS - len(new_sub_key)

                self.key_int = self.shift(self.key_int, SHIFT_BITS, KEY_SIZE)  # Make new shifted key
                key_bin_list = get_key_bin_list(self.key_int)
                [new_sub_key.append(x) for x in key_bin_list[:SUB_KEYS - len(new_sub_key)]]
                self.enc_sub_keys_list.append(new_sub_key[:SUB_KEYS])
            else:
                new_sub_key = temp[:6]
                to_remove = 6
                self.enc_sub_keys_list.append(new_sub_key[:SUB_KEYS])

        self.enc_sub_keys_list[-1] = self.enc_sub_keys_list[-1][0:4]
        return self.enc_sub_keys_list

    def decryption_key_schedule(self):
        sub_keys_list = []
        inv_sub_keys_list = [0] * 52
        [[sub_keys_list.append(int(x, 2)) for x in lst] for lst in self.enc_sub_keys_list]

        p = 0
        inv_sub_keys_list[48] = self.mulInv(sub_keys_list[p])  # 48 <- 0
        inv_sub_keys_list[49] = self.addInv(sub_keys_list[p + 1])  # 49 <- 1
        inv_sub_keys_list[50] = self.addInv(sub_keys_list[p + 2])  # 50 <- 2
        inv_sub_keys_list[51] = self.mulInv(sub_keys_list[p + 3])  # 51 <- 3
        p += 4
        for i in reversed(range(1, ROUNDS - 1)):
            r = i * 6
            inv_sub_keys_list[r + 4] = sub_keys_list[p]  # 46 <- 4
            inv_sub_keys_list[r + 5] = sub_keys_list[p + 1]  # 47 <- 5
            inv_sub_keys_list[r] = self.mulInv(sub_keys_list[p + 2])  # 42 <- 6
            inv_sub_keys_list[r + 2] = self.addInv(sub_keys_list[p + 3])  # 44 <- 7
            inv_sub_keys_list[r + 1] = self.addInv(sub_keys_list[p + 4])  # 43 <- 8
            inv_sub_keys_list[r + 3] = self.mulInv(sub_keys_list[p + 5])  # 45 <- 9
            p += 6

        inv_sub_keys_list[4] = sub_keys_list[46]  # 6 <- 46
        inv_sub_keys_list[5] = sub_keys_list[47]  # 5 <- 47
        inv_sub_keys_list[0] = self.mulInv(sub_keys_list[48])  # 0 <- 48
        inv_sub_keys_list[1] = self.addInv(sub_keys_list[49])  # 1 <- 49
        inv_sub_keys_list[2] = self.addInv(sub_keys_list[50])  # 2 <- 50
        inv_sub_keys_list[3] = self.mulInv(sub_keys_list[51])  # 3 <- 51

        temp = []
        for key_value in inv_sub_keys_list:
            temp.append(str(bin(key_value))[2:])
        for i in range(0, 48, 6):
            self.dec_sub_keys_list.append(temp[i:i + 6])
        self.dec_sub_keys_list.append(temp[48:52])

        return self.dec_sub_keys_list


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


if __name__ == "__main__":
    print('Please run IDEA.py or MainProgram.py')