from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac, padding
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import threading

import json
import util
import settings
import selectors
import socket
import os

VALID_SYMMETRIC_ALGORITHMS = ['AES-256', 'DES-128']

sel = selectors.DefaultSelector()

def do_handshake(conn):
    # generate private key, TODO: check if this elliptic function is safe
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()
    # encode public key into PEM format
    public_key_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    # create header containing which algorithms the client supports and
    # how long the send public key is.
    header = util.create_algorithm_header_client(VALID_SYMMETRIC_ALGORITHMS, len(public_key_bytes))
    conn.send(header)
    conn.send(public_key_bytes)

    # receive symmetric algorithm and public key len from the server
    server_choices_data = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    server_config = json.loads(server_choices_data)
    # verify chosen key from server
    algorithm = server_config['algorithm']
    if algorithm not in VALID_SYMMETRIC_ALGORITHMS:
        raise Exception("server picked unsupported algorithm")
    
    print(f"server picked {algorithm} as symmetric encryption algorithm")
    # receive the servers public key
    server_public_key_bytes = conn.recv(server_config['public_key_len'])
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    print("received public key:", server_public_key_bytes)

    # get the shared key and derive a new key from the shared key
    shared_key = private_key.exchange(
        ec.ECDH(), server_public_key
    )    
    derived_key = HKDF(
        algorithm=settings.HASH_ALGORITHM(),
        length=32,
        salt=None,
        info=None
    ).derive(shared_key)

    # sign all the data received from the server with the derived key.
    # the server can validate that each message that it send
    # is unchanged.
    handshake_data = server_choices_data + server_public_key_bytes
    signed_handshake = util.sign_message(handshake_data, derived_key)
    conn.send(signed_handshake.ljust(settings.HANDHSAKE_HEADER_LEN))

    # receive the HMAC of the messages the server received from us,
    # so we can verify that the messages we send have arrived unchanged
    server_handshake_hmac = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    server_handshake_hmac = server_handshake_hmac.rstrip()

    h = hmac.HMAC(derived_key, settings.HASH_ALGORITHM())
    h.update(header)
    h.update(public_key_bytes)

    try:
        h.verify(server_handshake_hmac)
    except exceptions.InvalidSignature as e:
        raise Exception("handshake HMAC could not be verified!")
    
    print(f"Handshake verified! Further communication with server localhost:9000 is now encrypted with {algorithm}")

    (server_aes_keys, client_aes_keys) = util.derive_symmetric_keys_from_shared_key(shared_key)
    print(server_aes_keys)
    print(client_aes_keys)
    key_data = {
        "shared_key": shared_key,
        "client_public_key": public_key,
        "client_private_key": private_key,
        "server_public_key": server_public_key,
        "server_cipher": Cipher(algorithms.AES256(server_aes_keys["key"]), modes.CBC(server_aes_keys["iv"])),
        "client_cipher": Cipher(algorithms.AES256(client_aes_keys["key"]), modes.CBC(client_aes_keys["iv"])),
    }

    listen_for_msg_thread = threading.Thread(target=get_messages, args=(conn, key_data))
    listen_for_msg_thread.start()
    # send(conn, msg, key_data)
    sel.register(conn, selectors.EVENT_READ, key_data)


################### Send Socket Messages ###################
    
def get_messages(conn, key_data):
    while True:
        msg = input("> ")
        send(conn, msg, key_data)


################### Socket stuff ###################
    
def send(conn, msg, key_data):
    ciphertext = util.encrypt_msg(msg, key_data["client_cipher"])

    conn.send(ciphertext)
    
def recv(conn, key_data):
    data = conn.recv(1024)
    addr = conn.getpeername()
    if data:
        msg = util.decrypt_msg(data, key_data["server_cipher"])
        util.print_peer_message(msg, "Server")
    else:
        sel.unregister(conn)
        close(conn)
        os._exit(0)
        return
    

def close(conn):
    addr = conn.getpeername()
    print(f"closing connection to {addr[0]}:{addr[1]}")

    conn.close()

def start_client():
    conn = socket.create_connection(('localhost', 9000))
    print("connected to server localhost:9000")
    try:
        do_handshake(conn)
    except Exception as e:
        print(e)
        print(f"invalid handshake")
        conn.close()
        return

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                key_data = key.data
                if mask & selectors.EVENT_READ:
                    recv(key.fileobj, key_data)

    except KeyboardInterrupt:
        print("Closing server...")
        os._exit(0)

if __name__ == "__main__":
    start_client()