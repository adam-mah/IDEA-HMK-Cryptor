from server.socket import Socket

soc = Socket()
sender = soc.sender
receiver = soc.receiver

sender.send_file("files/orig.txt")
soc.close_connection()
