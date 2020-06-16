from server.receiver import Receiver
from server.sender import Sender
import inspect


class Socket:
    def __init__(self):
        print("-> Connection socket created successfully.\n-> Authenticating...")
        self.receiver = Receiver(self)
        self.sender = Sender(self, self.receiver.send_key())
        print("-> Authentication Complete\n---------------------------------------------------------------------")

    def send(self, M):
        stack = inspect.stack()
        the_class = stack[1][0].f_locals["self"].__class__.__name__
        if the_class == 'Sender':  # M[0] contains the cipher , M[1] contains signature
            print("\n------SENDER------")
            print('-> Sending message to receiver')
            print("-> Sent message: " + M[0])
            self.receiver.receive(M[0], M[1])
        else:
            print("Invalid calling class")
