import rsa
import socket
import threading

FORMAT = 'ascii'

pubkey, privkey = rsa.newkeys(512) 

partner_pubkey = None


choice = input("Do you want to be the (h)ost or (c)lient:: ")

if choice.lower() == 'h':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("10.0.0.52", 5050))
    server.listen()

    client, addr = server.accept()
    client.send(pubkey.save_pkcs1(format='PEM'))
    partner_pubkey = rsa.PublicKey.load_pkcs1(client.recv(2048))
elif choice.lower() == 'c':
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("10.0.0.52", 5050))
    
    partner_pubkey = rsa.PublicKey.load_pkcs1(client.recv(2048))
    client.send(pubkey.save_pkcs1(format='PEM'))

else:
    exit()

def send_message(conn):
    while True:
        msg = input("")
        conn.send(rsa.encrypt(msg.encode(FORMAT), partner_pubkey))
        print("You: ", msg)

def receive_message(conn):
    while True:
        print("partner: ", rsa.decrypt(conn.recv(2048), privkey).decode(FORMAT))


threading.Thread(target=send_message, args=(client,)).start()
threading.Thread(target=receive_message, args=(client,)).start()