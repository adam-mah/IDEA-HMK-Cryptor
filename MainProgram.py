from server.socket import Socket

soc = Socket()
sender = soc.sender

sender.send_file("files/orig.txt")
soc.close_connection()
