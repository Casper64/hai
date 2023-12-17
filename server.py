from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography import exceptions
import json
import selectors
import settings
import socket
import util

sel = selectors.DefaultSelector()

VALID_SYMMETRIC_ALGORITHMS = ['AES-256']

################### Handshake ###################

def do_handshake(conn, addr):
    # generate private key, TODO: check if this elliptic function is safe
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()
    # encode public key into PEM format
    public_key_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    # receive client preferences
    client_preferences_data = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    client_config = json.loads(client_preferences_data)
    
    # receive peer public key
    peer_public_key_bytes = conn.recv(client_config['public_key_len'])
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
    print("received public key:", peer_public_key_bytes)

    # get the shared key and derive a new key from the shared key
    shared_key = private_key.exchange(
        ec.ECDH(), peer_public_key
    )    
    derived_key = HKDF(
        algorithm=settings.HASH_ALGORITHM(),
        length=32,
        salt=None,
        info=None
    ).derive(shared_key)

    algorithm = util.pick_algorithm(VALID_SYMMETRIC_ALGORITHMS, client_config)
    if algorithm is None:
        raise Exception("Client sent weak/invalid algorithms")
    print(f"Picked algorithm {algorithm} as symmetric encryption algorithm")

    header = util.create_header_server(algorithm, len(public_key_bytes))
    conn.send(header)
    conn.send(public_key_bytes)

    handshake_data = client_preferences_data + peer_public_key_bytes
    signed_handshake = util.sign_message(handshake_data, derived_key)

    conn.send(signed_handshake.ljust(settings.HANDHSAKE_HEADER_LEN))

    client_handshake_hmac = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    client_handshake_hmac = client_handshake_hmac.rstrip()

    h = hmac.HMAC(derived_key, settings.HASH_ALGORITHM())
    h.update(header)
    h.update(public_key_bytes)

    try:
        h.verify(client_handshake_hmac)
    except exceptions.InvalidSignature as e:
        raise Exception("handshake HMAC could not be verified!")


    print(f"Handshake verified! Further communication with peer {addr[0]}:{addr[1]} is now encrypted with {algorithm}")

################### Socket stuff ###################

def accept(sock, mask):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr[0]}:{addr[1]}")

    try:
        do_handshake(conn, addr)
    except Exception as e:
        print(e)
        print(f"invalid handshake from client {addr[0]}:{addr[1]}")
        conn.close()
        return

def recv(conn, mask):
    data = conn.recv(1024)
    addr = conn.getpeername()
    if data:
        print("sending", repr(data), f"to {addr[0]}:{addr[1]}")
        conn.send(data)
    else:
        sel.unregister(conn)
        close(conn)

def send():
    pass

def close(conn):
    addr = conn.getpeername()
    print(f"closing connection to {addr[0]}:{addr[1]}")

    conn.close()

def bind_and_listen(host, port):
    sock = socket.create_server((host, port), family=socket.AF_INET, backlog=128, reuse_port=True)
    sock.setblocking(False)

    print(f"Server is listening at {host}:{port}")

    return sock

def start_server():
    sock = bind_and_listen('localhost', 9000)
    sel.register(sock, selectors.EVENT_READ, accept)

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
    except KeyboardInterrupt:
        print("Closing server...")

if __name__ == "__main__":
    start_server()

