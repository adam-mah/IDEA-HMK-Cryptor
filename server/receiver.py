from DSA import DSA
from HMKnapsack import HMKnapsack

KEY_SIZE = 128


class Receiver():
    def __init__(self, socket):
        self.socket = socket
        print("\n------RECEIVER------")
        print("Generating private and public keys...")
        self.hmk_cryptor = HMKnapsack(KEY_SIZE)

    def send_key(self):
        print("Sending {0}...] public key to sender...".format(str(self.hmk_cryptor.get_public_key())[:10]))
        return self.hmk_cryptor.get_public_key()

    def get_encryption_keys(self, ciphered_key, signed_idea, DSA_keys):
        print("\n------RECEIVER------\n")
        print("Received encrypted IDEA Key, decrypting...")
        self.idea_key = self.hmk_cryptor.decrypt(ciphered_key)
        print("Decrypted IDEA Key: " + self.idea_key)

        self.p, self.q, self.g, self.pkey = DSA_keys
        self.verify_message(ciphered_key, signed_idea[0], signed_idea[1])

    def receive(self):
        pass

    def verify_message(self, M, r, s):
        if DSA.verify(M, r, s, self.p, self.q, self.g, self.pkey):
            print('Result: Verified!')
        else:
            print("Result: Verification failed!")
