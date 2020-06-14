from DSA import DSA
from HMKnapsack import HMKnapsack
from pckgIDEA.IDEA import IDEA


class Sender:
    def __init__(self, socket, hmk_pkey):
        self.socket = socket
        print("\n------SENDER------")
        self.signer = DSA()
        self.hmk_pkey = hmk_pkey
        print("Received public key {0}...] from receiver...".format(str(self.hmk_pkey)[:10]))
        print("Generating and encrypting IDEA key using HMKnapsack receiver public key")
        KEY = int('321207699978693532835173521553042405267')
        idea_cryptor = IDEA(KEY)
        ciphered_IDEA_key = HMKnapsack.encrypt(str(idea_cryptor.key), self.hmk_pkey)
        print("Key {1} was generated successfully and encrypted and signed\n"
              "Sending signature and encrypted IDEA Key [{0}...]".format(str(ciphered_IDEA_key)[:10], KEY))

        socket.receiver.get_encryption_keys(ciphered_IDEA_key, self.sign_message(ciphered_IDEA_key),
                                            self.signer.get_keys())

    def send(self):
        pass

    def sign_message(self, M):
        r, s = self.signer.sign(M)
        return r, s
