from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import json
import selectors
import settings
import socket
import util
import threading

import os

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
    # receive clients public key
    client_public_key_bytes = conn.recv(client_config['public_key_len'])
    # load public key from PEM format
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
        
    print("received public key:", client_public_key_bytes)

    # get the shared key and derive a new key from the shared key
    shared_key = private_key.exchange(
        ec.ECDH(), client_public_key
    )    
    derived_key = HKDF(
        algorithm=settings.HASH_ALGORITHM(),
        length=32,
        salt=None,
        info=None
    ).derive(shared_key)

    # pick the strongest algorithm that the client supports
    algorithm = util.pick_algorithm(VALID_SYMMETRIC_ALGORITHMS, client_config)
    if algorithm is None:
        # the client doesn't support any of the algorithms we define as strong
        raise Exception("Client sent weak/invalid algorithms")
    print(f"Picked algorithm {algorithm} as symmetric encryption algorithm")

    # let the client know which algorithm we picked and send our public key
    header = util.create_algorithm_header_server(algorithm, len(public_key_bytes))
    conn.send(header)
    conn.send(public_key_bytes)

    # sign all the data received from the client with the derived key.
    # the client can validate that each message that it send
    # is unchanged.
    handshake_data = client_preferences_data + client_public_key_bytes
    signed_handshake = util.sign_message(handshake_data, derived_key)
    conn.send(signed_handshake.ljust(settings.HANDHSAKE_HEADER_LEN))

    # receive the HMAC of the messages the client received from us,
    # so we can verify that the messages we send have arrived unchanged
    client_handshake_hmac = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    client_handshake_hmac = client_handshake_hmac.rstrip()

    h = hmac.HMAC(derived_key, settings.HASH_ALGORITHM())
    h.update(header)
    h.update(public_key_bytes)

    try:
        h.verify(client_handshake_hmac)
    except exceptions.InvalidSignature:
        raise Exception("handshake HMAC could not be verified!")


    print(f"Handshake verified! Further communication with peer {addr[0]}:{addr[1]} is now encrypted with {algorithm}")
    
    (server_aes_keys, client_aes_keys) = util.derive_symmetric_keys_from_shared_key(shared_key)
    print(server_aes_keys)
    print(client_aes_keys)
    key_data = {
        "shared_key": shared_key,
        "client_public_key": client_public_key,
        "server_public_key": public_key,
        "server_private_key": private_key,
        "server_cipher": Cipher(algorithms.AES256(server_aes_keys["key"]), modes.CBC(server_aes_keys["iv"])),
        "client_cipher": Cipher(algorithms.AES256(client_aes_keys["key"]), modes.CBC(client_aes_keys["iv"])),
    }

    listen_for_msg_thread = threading.Thread(target=get_messages, args=(conn, key_data))
    listen_for_msg_thread.start()
    sel.register(conn, selectors.EVENT_READ, key_data)

    
################### Send Socket Messages ###################
    
def get_messages(conn, key_data):
    while True:
        msg = input("> ")
        send(conn, msg, key_data)


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

    
def send(conn, msg, key_data):
    ciphertext = util.encrypt_msg(msg, key_data["server_cipher"])

    conn.send(ciphertext)
    
def recv(conn, key_data):
    data = conn.recv(1024)
    addr = conn.getpeername()
    if data:
        msg = util.decrypt_msg(data, key_data["client_cipher"])
        util.print_peer_message(msg, f"{addr[0]}:{addr[1]}")
    else:
        sel.unregister(conn)
        close(conn)
        return

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
    sel.register(sock, selectors.EVENT_READ)

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                key_data = key.data
                if mask & selectors.EVENT_READ:
                    if key_data is None:
                        accept(key.fileobj, mask)
                    else:
                        recv(key.fileobj, key_data)


    except KeyboardInterrupt:
        print("Closing server...")
        os._exit(0)

if __name__ == "__main__":
    start_server()

