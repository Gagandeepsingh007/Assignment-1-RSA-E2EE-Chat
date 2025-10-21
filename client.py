import socket 
import threading
import time
import rsa
import json

HEADER = 64
PORT = 5051
FORMAT = 'ascii'
SERVER = "10.0.0.52"
ADDR = (SERVER, PORT)   
DISCONNECT_MESSAGE = "!DIS"
GET_PUB_KEYS = "!GETPUBKEYS"

# generate keys
pubkey, privkey = rsa.newkeys(512) 

# print (str(pubkey).encode(FORMAT))



NAME = input("Enter your name: ")

# def log_message(msg, addr):
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)
# def log_message(msg, addr):
# def log_message(msg, addr):

pubkeys = None

def writeinjson(log_data):
    try:
        with open(f'{NAME}_log.json', "r") as f_log:
            data = json.load(f_log)
    except FileNotFoundError:
        data = []
    except json.JSONDecodeError:
        data = []

    data.append(log_data)

    with open(f'{NAME}_log.json', "w") as f_log:
        json.dump(data, f_log, indent=4)

def send(msg):
    # msg should be bytes
    if isinstance(msg, str):
        message = msg.encode(FORMAT)
    else:
        message = msg
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.sendall(send_length)
    client.sendall(message)

def listen_for_messages():
    global pubkeys
    try:
        while True:
            # read exact HEADER then payload
            raw_len = client.recv(HEADER)
            if not raw_len:
                break
            try:
                msg_length = int(raw_len.decode(FORMAT).strip())
            except Exception:
                continue
            data = b""
            while len(data) < msg_length:
                packet = client.recv(msg_length - len(data))
                if not packet:
                    break
                data += packet
            if not data:
                break

            # check control message
            try:
                text = data.decode(FORMAT)
            except Exception:
                text = None

            if text == GET_PUB_KEYS:
                # next message is public key bytes
                raw_len = client.recv(HEADER)
                if not raw_len:
                    break
                try:
                    pk_len = int(raw_len.decode(FORMAT).strip())
                except Exception:
                    continue
                pk_bytes = b""
                while len(pk_bytes) < pk_len:
                    p = client.recv(pk_len - len(pk_bytes))
                    if not p:
                        break
                    pk_bytes += p
                if pk_bytes:
                    pubkeys = rsa.PublicKey.load_pkcs1(pk_bytes)
                    print(f"[PUBLIC KEY RECEIVED] Public key received from server.")
                continue

            # otherwise treat data as encrypted bytes and attempt to decrypt
            try:
                plain = rsa.decrypt(data, privkey)
                print(plain.decode(FORMAT))
                # logging the message in the json file
                msg_info = plain.decode(FORMAT).split(": ", 1)
                if len(msg_info) == 2:
                    json_entry = {"sender": msg_info[0], "message": msg_info[1], "ciphertext": data.hex(),"timestamp": time.time()}
                    writeinjson(json_entry)
            except Exception as e:
                # Not able to decrypt as RSA encrypted message; print raw
                try:
                    print(data.decode(FORMAT))
                    # logging the message in the json file
                    msg_info = plain.decode(FORMAT).split(": ", 1)
                    if len(msg_info) == 2:
                        json_entry = {"sender": msg_info[0], "message": msg_info[1], "ciphertext": "Not encrypted Correctly","timestamp": time.time()}
                        writeinjson(json_entry)
                except Exception as e:
                    print("Received non-text/non-decryptable message", e)
    except Exception as e:
        print("Connection ended with an error (IGNORE [WinError 10038]): ", e)
def start_listening():
        try:
            pk = pubkey.save_pkcs1(format='PEM')
            # send public key with header
            send(pk)
            print("SENT PUBLIC KEY TO SERVER.")
            thread = threading.Thread(target=listen_for_messages)
            thread.start()
            while True:
                msg = input()
                if msg == DISCONNECT_MESSAGE:
                    send(DISCONNECT_MESSAGE)
                    print("Disconnected from the server.")
                    client.close()
                    break
                elif msg:
                    if pubkeys is not None:
                        msg = f"{NAME}: {msg}"
                        encrypted = rsa.encrypt(msg.encode(FORMAT), pubkeys)
                        # send raw encrypted bytes (not embedded in a formatted string)
                        # include sender name in plaintext before encrypting if needed
                        send(encrypted)
                        
                        # logging the message in the json file
                        json_entry = {"sender": NAME, "message": msg, "ciphertext": encrypted.hex(),"timestamp": time.time()}
                        writeinjson(json_entry)
                    else:
                        print("No public keys available yet.")
                        
        except Exception as e:
            print("Error sending message: ", e)

start_listening()
