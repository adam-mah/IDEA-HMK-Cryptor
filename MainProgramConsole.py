from server.socket import Socket

# soc = Socket()
# sender = soc.sender
# sender.send_file("files/lorem.txt")
# soc.close_connection()

def send_text(text):
    while text != '':
        soc.sender.send(text[:8])
        text = text[8:]


def send_choice():
    choice = int(input("Sending type:\n    1-Send text\n    2-Send file\n    3-Send Lorem ipsum\n   Choice: "))
    while True:
        if choice == 1:
            while True:
                print('Type \'exit\' to close program')
                text = str(input("Input text to send: "))
                if text == 'exit':
                    soc.close_connection()
                    exit()
                else:
                    send_text(text+'\n')
        elif choice == 2:
            file = str(input("Input .txt file name: "))
            soc.sender.send_file(file)
            print("-------\nFile sent successfully to receiver!")
            soc.close_connection()
            exit()
        elif choice == 3:
            soc.sender.send_file("files/lorem.txt")
            print("-------\nFile sent successfully to receiver!")
            soc.close_connection()
            break#exit()
        else:
            print("Invalid input")


print("**Text Cryptor**")
while True:
    choice = int(input("Options:\n      1-Create secure connection and authenticate\n      2-Exit\n      Choice: "))
    if choice == 1:
        while True:
            choice = int(input(
                "Choose key generation method:\n     1-Generate random IDEA encryption key\n     2-Use custom encryption key\n     Choice: "))
            if choice == 1:
                soc = Socket()
                send_choice()
                break
            elif choice == 2:
                while True:
                    key = str(input("IDEA encryption key (32-Hex Digits): "))
                    if len(key) == 32:
                        try:
                            key = int(key, 16)
                            break
                        except:
                            print("Invalid key, insert 32 Hex digits")
                    print("Invalid key length, insert 32 Hex digits")
                soc = Socket(key)
                send_choice()
            else:
                print('Invalid input')
    elif choice == 2:
        exit()
    else:
        print('Invalid input')
