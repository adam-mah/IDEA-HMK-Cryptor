from server.receiver import Receiver
from server.sender import Sender


class Socket():
    def __init__(self):
        print("Connection socket created successfully.\nAuthenticating...")
        self.receiver = Receiver(self)
        self.sender = Sender(self, self.receiver.send_key())



