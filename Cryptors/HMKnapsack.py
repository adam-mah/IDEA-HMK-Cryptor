import secrets

import numpy as np
import sympy

MAX_CHARS = 128  # Maximum input length


def check_sequence(sequence):
    total = 0
    isSuperInc = True
    for n in sequence:
        print("Sum: ", total, "Element: ", n, "Sub:", n - total)
        if n <= total:
            isSuperInc = False
            break
        total += n
    return isSuperInc


def get_binary_string(string_input):
    """
    Generate binary string from input string
    :param string_input: user input string
    :return: binary_string: binary input string
    """
    binary_str = ""
    for char in string_input:
        binary_str = binary_str + f'{ord(char):08b}'

    return binary_str


def get_plain_text(plain_text_bits):
    """
    Generate binary string from input string
    :param plain_text_bits: decrypted binary message
    :return: binary_string: binary input string
    """
    plain_text_bits = ''.join([str(elem) for elem in plain_text_bits])  # Convert binary list to a string
    split_into_bytes = []

    for index in range(0, len(plain_text_bits), 8):
        split_into_bytes.append(plain_text_bits[index: index + 8])  # Divide string to bytes into a list

    plain_text = ''.join(
        [chr(int(elem, 2)) for elem in split_into_bytes])  # Convert bytes to ASCII and concat decrypted string

    return plain_text


class HMKnapsack():
    def __init__(self, len=None):
        if len is not None:
            self.w, self.q, self.r = self.generate_keys(len)
            self.b = self.generate_public_key()

    def get_private_keys(self):
        return self.w, self.q, self.r

    def get_public_key(self):
        return self.b

    @staticmethod
    def generate_keys(plain_text_length):
        '''
        Generate a superincreasing sequence w
        and q and r keys
        :return: w, q ,r
        '''

        # Generating w super-increasing sequence
        w = [0] * plain_text_length * 8
        w[0] = np.random.randint(2, high=5)

        sum = w[0]
        for i in range(1, len(w)):
            w[i] = sum + np.random.randint(2, high=5)
            sum += w[i]

        # Generating q where q is a random integer bigger than the total sum of w array
        q = sum + np.random.randint(2, high=5)

        # We take r to be q-1 as it will be the co-prime of q
        r = q - 1

        return w, q, r

    def generate_public_key(self):
        """
        Generating public key based on w q r
        :param w: Super-increasing Sequence
        :param q: q > [sum of w] , modulo value
        :param r: co-prime number of q
        :return: public key b
        """
        public_key = []
        for i in range(0, len(self.w)):
            public_key.append(self.w[i] * self.r % self.q)

        #public_key = list(map(int, public_key))  # For some reason the list gets a float numbers inserted... removing
        # this line will crash the code on large input

        return public_key

    @staticmethod
    def encrypt(plain_text, b):
        """
        :param plain_text: input message to encrypt
        :param b: public key
        :return: ciphered text
        """
        binary_plain_text = get_binary_string(plain_text)
        cipher_text = 0
        for i in range(len(plain_text) * 8):  # Length of b and binary input
            cipher_text += int(binary_plain_text[i]) * b[i]

        return cipher_text

    def decrypt(self, cipher_text):
        """
        Decrypt cipher text
        :param cipher_text: Encrypted text
        :param w: Super-increasing Sequence
        :param q: q > [sum of w] , modulo value
        :param r: co-prime number of q
        :return: Decrypted cipher (plain_text)
        """
        r_inverse = sympy.mod_inverse(self.r, self.q)
        temp = int(np.mod(cipher_text * r_inverse, self.q))

        plain_text_bits = []
        for i in self.w[::-1]:
            if i <= temp:
                # print("{0} - {1} = {2}".format(temp, i, temp-i))  # Calculations stop when temp = 0
                temp = temp - i
                plain_text_bits.insert(0, 1)
            else:
                # print("Skip " + str(i))
                plain_text_bits.insert(0, 0)

        return get_plain_text(plain_text_bits)


if __name__ == "__main__":
    # w = [2, 7, 11, 21, 42, 89, 180, 354]
    # q = 881
    # r = 588

    # while True:
    #     plain_text = input("Insert a message to encrypt: ")
    #     if len(plain_text) <= MAX_CHARS:
    #         break
    #     else:
    #         print("Input must be shorter than 128chars")
    # w, q, r = generate_keys(len(plain_text))  # Generate encryption keys
    # b = generate_public_key(w, q, r)  # Public Key
    #
    # cipher_text = hmk_encrypt(plain_text, b)  # Encrypted plain text
    # decrypted_cipher_text = hmk_decrypt(cipher_text, w, q, r)  # Decrypted cipher
    # print("Encrypted message: {0} \nDecrypted message: {1}".format(cipher_text, decrypted_cipher_text))
    KEY_SIZE = 128
    KEY = str(secrets.randbits(KEY_SIZE))
    hmkCryptor = HMKnapsack(KEY_SIZE)
    cipher_text = hmkCryptor.encrypt(KEY, hmkCryptor.get_public_key())
    decrypted_cipher_text = hmkCryptor.decrypt(cipher_text)
    print("Original message:  {0}\nEncrypted message: {1} \nDecrypted message: {2}".format(KEY, cipher_text, decrypted_cipher_text))
