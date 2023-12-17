from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography import exceptions
import json
import util
import settings
import socket

VALID_SYMMETRIC_ALGORITHMS = ['AES-256', 'DES-128']

def do_handshake(conn):
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    public_key = private_key.public_key()
    # encode public key into PEM format
    public_key_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    header = util.create_header_client(VALID_SYMMETRIC_ALGORITHMS, len(public_key_bytes))

    conn.send(header)
    conn.send(public_key_bytes)

    server_choices_data = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    server_config = json.loads(server_choices_data)

    algorithm = server_config['algorithm']
    if algorithm not in VALID_SYMMETRIC_ALGORITHMS:
        raise Exception("server picked unsupported algorithm")
    
    print(f"server picked {algorithm} as symmetric encryption algorithm")

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

    handshake_data = server_choices_data + server_public_key_bytes
    signed_handshake = util.sign_message(handshake_data, derived_key)

    conn.send(signed_handshake.ljust(settings.HANDHSAKE_HEADER_LEN))

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


################### Socket stuff ###################

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

if __name__ == "__main__":
    start_client()