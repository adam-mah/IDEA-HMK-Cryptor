import grpc

credentials = grpc.ssl_channel_credentials()
channel = grpc.secure_channel('127.0.0.1', credentials)
print(grpc.channel_ready_future(channel))