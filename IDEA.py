import random
import numpy

KEY_SIZE = 128


class IDEA:
    def __init__(self):
        self.sub_keys = []
        self.key = random.getrandbits(KEY_SIZE)

        self.rol = lambda val, r_bits, max_bits: \
            (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
            ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

    def key_scheduler(self):  # Prepares all sub keys for the 8.5 rounds
        pass

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


class IDEA_Key_Scheduler:
    def __init__(self):
        pass


cryptor = IDEA()
print(cryptor.get_sub_keys())
# cryptor.generate_next_key()
