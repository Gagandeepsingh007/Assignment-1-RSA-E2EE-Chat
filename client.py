import socket 
import threading
import time
import rsa
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

HEADER = 64
PORT = 5051
FORMAT = 'ascii'
SERVER = "10.0.0.52"
ADDR = (SERVER, PORT)   
DISCONNECT_MESSAGE = "!DIS"
GET_PUB_KEYS = "!GETPUBKEYS"
AES_START = "!AESSTART"
AES_USE = False

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
aes_key = None

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
    global AES_START
    # msg should be bytes
    if isinstance(msg, str):
        message = msg.encode(FORMAT)
    else:
        message = msg

    if msg == AES_START:
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.sendall(send_length)
        client.sendall(message)
        return

    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.sendall(send_length)
    client.sendall(message)

def listen_for_messages():
    global pubkeys
    global aes_key
    global AES_USE

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

            if text == AES_START:
                # next message is AES key bytes
                raw_len = client.recv(HEADER)
                AES_USE = True
                if not raw_len:
                    break
                try:
                    aes_len = int(raw_len.decode(FORMAT).strip())
                except Exception:
                    continue
                aes_bytes = b""
                while len(aes_bytes) < aes_len:
                    p = client.recv(aes_len - len(aes_bytes))
                    if not p:
                        break
                    aes_bytes += p
                if aes_bytes:
                    aes_data = base64.urlsafe_b64decode(aes_bytes)
                    # Just store the key, no IV stored globally
                    aes_key = rsa.decrypt(aes_data, privkey)
                    print(f"[DEBUG] AES key received and decrypted: {aes_key.hex()} (length: {len(aes_key)})")
                    AES_USE = True
                    print(f"[AES KEY RECEIVED] AES key received from server.")
                continue

            # otherwise treat data as encrypted bytes and attempt to decrypt
            try:
                if AES_USE:
                    # CBC mode - IV is prepended to ciphertext
                    # print(f"[DEBUG] Received {len(data)} bytes, AES key length: {len(aes_key) if aes_key else 0}")
                    aes_iv = data[:16]
                    ciphertext = data[16:]
                    # print(f"[DEBUG] IV: {aes_iv.hex()[:32]}... Ciphertext: {len(ciphertext)} bytes")
                    decipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                    plain = unpad(decipher.decrypt(ciphertext), AES.block_size)
                else:
                    plain = rsa.decrypt(data, privkey)
                print(plain.decode(FORMAT))
                # logging the message in the json file
                msg_info = plain.decode(FORMAT).split(": ", 1)
                if len(msg_info) == 2:
                    json_entry = {"sender": msg_info[0], "message": msg_info[1], "ciphertext": data.hex(),"timestamp": time.time()}
                    writeinjson(json_entry)
            except Exception as e:
                print(f"[ERROR] Decryption failed: {e}")
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
        global aes_key
        global AES_USE
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
                elif msg == AES_START:
                    if pubkeys is not None:
                        # generate AES key only (no IV stored globally)
                        aes_key = get_random_bytes(16)
                        print(f"[DEBUG] Generated AES key: {aes_key.hex()} (length: {len(aes_key)})")
                        # RSA-encrypt the AES key with receiver's public key
                        encrypted_aes_key = rsa.encrypt(aes_key, pubkeys)
                        aes_data = base64.urlsafe_b64encode(encrypted_aes_key)
                        print(aes_data)
                        send(AES_START)

                        send(aes_data)
                        AES_USE = True
                        print("AES encryption started.")
                    else:
                        print("No connections available yet.")
                elif msg:
                    if pubkeys is not None:
                        msg = f"{NAME}: {msg}"
                        if AES_USE:
                            # CBC mode - generate fresh IV for each message
                            aes_iv = get_random_bytes(16)
                            # print(f"[DEBUG] Encrypting with AES key length: {len(aes_key)}, IV: {aes_iv.hex()[:32]}...")
                            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                            ciphertext = cipher.encrypt(pad(msg.encode(FORMAT), AES.block_size))
                            # Prepend IV to ciphertext
                            encrypted = aes_iv + ciphertext
                            # print(f"[DEBUG] Sending {len(encrypted)} bytes (16 IV + {len(ciphertext)} ciphertext)")
                            send(encrypted)
                            
                            # logging the message in the json file
                            json_entry = {"sender": NAME, "message": msg, "ciphertext": encrypted.hex(),"timestamp": time.time()}
                            writeinjson(json_entry)

                        else:
                            encrypted = rsa.encrypt(msg.encode(FORMAT), pubkeys)
                            # send raw encrypted bytes (not embedded in a formatted string)
                            # include sender name in plaintext before encrypting if needed
                            send(encrypted)
                            
                            # logging the message in the json file
                            json_entry = {"sender": NAME, "message": msg, "ciphertext": encrypted.hex(),"timestamp": time.time()}
                            writeinjson(json_entry)
                    else:
                        print("No connections available yet.")
                        
        except Exception as e:
            print("Error sending message: ", e)

start_listening()
