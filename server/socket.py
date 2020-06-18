from server.receiver import Receiver
from server.sender import Sender
import inspect


class Socket:
    def __init__(self, KEY=None):
        self.log_file = open("files/socket_data.txt", "w", encoding='utf-8')
        print("-> Connection socket created successfully.\n-> Authenticating...")
        self.receiver = Receiver(self)
        self.sender = Sender(self, self.receiver.send_key(), KEY)
        print("-> Authentication Complete\n---------------------------------------------------------------------")

    def send(self, M):
        stack = inspect.stack()
        the_class = stack[1][0].f_locals["self"].__class__.__name__
        if the_class == 'Sender':  # M[0] contains the cipher , M[1] contains signature
            print("\n------SOCKET------")
            print("-> Received message from sender"
                  "\n-> Message: {0}\n-> Sending message to receiver".format(M[0]))
            self.log_file.write(M[0])
            self.receiver.receive(M[0], M[1])
        else:
            print("Invalid calling class")

    def close_connection(self):

        self.log_file.close()
        self.receiver.rec_file.close()
        #del self.sender
        #del self.receiver
        #del self
        print("Connection terminated successfully")
