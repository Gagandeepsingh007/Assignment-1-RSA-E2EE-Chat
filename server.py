import socket
import threading
import time

HEADER = 64
PORT = 5051
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'ascii'
DISCONNECT_MESSAGE = "!DIS"
GET_PUB_KEYS = "!GETPUBKEYS"

print(SERVER)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

# each client is a dict: {"socket": <socket>, "public_key": <bytes>}
clients = []
clients_lock = threading.Lock()

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_message(conn):
    # reads HEADER bytes for length, then reads the payload
    raw_len = recv_exact(conn, HEADER)
    if not raw_len:
        return None
    try:
        msg_length = int(raw_len.decode(FORMAT).strip())
    except Exception:
        return None
    if msg_length == 0:
        return b""
    return recv_exact(conn, msg_length)

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    pubkey = recv_message(conn)
    if pubkey is None:
        print(f"[ERROR] Failed to receive public key from {addr}")
        conn.close()
        return
    print(f"[PUBLIC KEY RECEIVED] {addr} public key received.")
    with clients_lock:
        clients.append({"socket": conn, "public_key": pubkey})

    # After we have the new client's public key, notify all clients
    send_pubkeys()

    while connected:
        msg = recv_message(conn)
        if msg is None:
            break
        try:
            decoded = msg.decode(FORMAT)
        except Exception:
            decoded = None

        if decoded == DISCONNECT_MESSAGE:
            connected = False
            break
        if decoded == GET_PUB_KEYS:
            # ignore; server sends pubkeys proactively
            continue

        # broadcast raw bytes to other clients
        broadcast(msg, exclude_conn=conn)
        if decoded:
            print(decoded)

    # cleanup
    conn.close()
    # remove client by socket
    for c in clients:
        if c["socket"] == conn:
            clients.remove(c)
            break
    print(f"[DISCONNECTED] {addr} disconnected.")

def broadcast(msg_bytes, exclude_conn=None):
    # msg_bytes is raw bytes
    msg_length = len(msg_bytes)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    for client in list(clients):
        sock = client.get("socket")
        if sock == exclude_conn:
            continue
        try:
            sock.sendall(send_length)
            sock.sendall(msg_bytes)
        except Exception:
            # remove dead clients
            try:
                clients.remove(client)
            except ValueError:
                pass

def send_pubkeys():
    # For each connected client, send them the public keys of all other clients
    with clients_lock:
        snapshot = list(clients)

    for target in snapshot:
        target_sock = target["socket"]
        for client in snapshot:
            if client is target:
                continue
            try:
                # send GET_PUB_KEYS control
                payload = GET_PUB_KEYS.encode(FORMAT)
                send_length = str(len(payload)).encode(FORMAT)
                send_length += b' ' * (HEADER - len(send_length))
                target_sock.sendall(send_length)
                target_sock.sendall(payload)

                # then send the public key bytes
                pk = client["public_key"]
                pk_len = len(pk)
                send_length = str(pk_len).encode(FORMAT)
                send_length += b' ' * (HEADER - len(send_length))
                target_sock.sendall(send_length)
                target_sock.sendall(pk)
            except Exception:
                pass



def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}:{PORT}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()
        # time.sleep(1)
        print(f"\n[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

print("[STARTING] Server is starting...")
start()
