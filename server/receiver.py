from Cryptors.DSA import DSA
from Cryptors.HMKnapsack import HMKnapsack
from pckgIDEA.IDEA import IDEA

KEY_SIZE = 128


class Receiver():
    def __init__(self, socket):
        self.rec_file = open("files/receiver_decrypted.txt", "w", encoding="utf-8")
        self.socket = socket
        print("\n------RECEIVER------")
        print("Generating private and public keys...")
        self.hmk_cryptor = HMKnapsack(KEY_SIZE)

    def send_key(self):
        """
        Returns HMK public key to exchange with the sender
        :return:  HMK Public key
        """
        print("Sending {0}...] public key to sender...".format(str(self.hmk_cryptor.get_public_key())[:10]))
        return self.hmk_cryptor.get_public_key()

    def exchange_keys(self, ciphered_key, signed_idea, DSA_keys):
        print("\n------RECEIVER------\n")
        print("Received encrypted IDEA Key, verifying and decrypting...")
        self.DSA_keys = {'p': DSA_keys[0], 'q': DSA_keys[1], 'g': DSA_keys[2], 'pkey': DSA_keys[3]}

        if self.verify_message(ciphered_key, signed_idea[0], signed_idea[1]):
            idea_key = self.hmk_cryptor.decrypt(int(ciphered_key))
            idea_key = idea_key.rstrip('\x00')
            self.idea_cryptor = IDEA(int(idea_key))
            print("IDEA key was exchanged and verified successfully.")
            print("Decrypted IDEA Key: " + idea_key)
        else:
            print("Incorrect received IDEA key value")

    def receive(self, M, signature):
        print("\n------RECEIVER------")
        print("-> Message {0} received from sender".format(M))
        r, s = signature
        if self.verify_message(M, r, s):
            decrypted_text = self.idea_cryptor.decrypt(M)
            print("-> Verified, decrypted message: " + decrypted_text)
            self.rec_file.write(decrypted_text)

    def verify_message(self, M, r, s):
        """
        Verify message
        :param M: Received message
        :param r: signature
        :param s: signature
        :return: If the message is valid
        """
        if DSA.verify(M, r, s, self.DSA_keys['p'], self.DSA_keys['q'], self.DSA_keys['g'], self.DSA_keys['pkey']):
            # print('Result: Verified!')
            return True
        else:
            # print("Result: Verification failed!")
            return False
