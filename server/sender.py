from Cryptors.DSA import DSA
from Cryptors.HMKnapsack import HMKnapsack
from pckgIDEA.IDEA import IDEA


class Sender:
    def __init__(self, socket, hmk_pkey):
        self.socket = socket
        print("\n------SENDER------")
        self.signer = DSA()  # Create DSA signer
        self.hmk_pkey = hmk_pkey  # Exchanged HMK Public key from receiver
        print("Received public key {0}...] from receiver...".format(str(self.hmk_pkey)[:10]))
        print("Generating and encrypting IDEA key using HMKnapsack receiver public key")
        #KEY = 321207699978693532835173521553042405267
        self.idea_cryptor = IDEA()  # Initializing IDEA encryptor with KEY value
        ciphered_IDEA_key = HMKnapsack.encrypt(str(self.idea_cryptor.key),
                                               self.hmk_pkey)  # Encrypting IDEA Key with HMK public key
        print("Key {1} was generated successfully and encrypted and signed\n"
              "Sending signature and encrypted IDEA Key [{0}...]".format(str(ciphered_IDEA_key)[:10], self.idea_cryptor.key))
        print(self.idea_cryptor.key)

        socket.receiver.exchange_keys(ciphered_IDEA_key, self.sign_message(ciphered_IDEA_key), self.signer.get_keys())

    def send(self, M):
        print("\n------SENDER------")
        M = str(M)
        if len(M) <= 8:
            ciphered_text = self.idea_cryptor.encrypt(M)
            print("Original message: {0}\nCiphered message: {1}".format(M, ciphered_text))
            M = (ciphered_text, self.sign_message(ciphered_text))
            self.socket.send(M)
        else:
            print('Invalid message size, message must be shorter than 8')

    def sign_message(self, M):
        r, s = self.signer.sign(M)
        return r, s

    def send_file(self, path):
        in_file = open(path, "r", encoding="utf-8")
        bytes8 = in_file.read(8)
        while bytes8:
            self.send(bytes8)
            bytes8 = in_file.read(8)
        in_file.close()
