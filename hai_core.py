# This file contains all the core functionality of the messaging program:
# initial handshake, encryption/decryption of messages and the implementation
# of the `send`, `recv` and `accept` methods. The accept method is split
# into a client and a server handshake method. See the comments
from cryptography.hazmat.primitives import serialization, hmac, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography import exceptions

import json
import settings
import util
import os

### Socket recv, send, close ###

# build JSON data for a message of `type` and sign it
def build_message_header(type, message, key_data):
    data = {
        "type": type,
        "message": message,
        "hmac": sign_message(
            message.encode('utf-8'), 
            key_data["shared_key"]
        ).hex()
    }
    return data

# send `message` over the connection
def send(conn, message, key_data):
    # generate a new initialization vector for each message
    # this IV will be used for the next message.
    new_iv =  os.urandom(16)
    
    data = build_message_header("message", message, key_data)
    data["new_iv"] = new_iv.hex()
    raw = json.dumps(data)

    aes_data =  key_data["own_aes_data"]
    ciphertext = encrypt_msg(raw, aes_data["key"], aes_data["iv"])
    if len(ciphertext) > settings.MAX_MESSAGE_LEN:
        raise Exception("message is too long!")

    conn.send(ciphertext)

    # set the new IV
    aes_data["iv"] = new_iv

def recv(conn, key_data):
    ciphertext = conn.recv(settings.MAX_MESSAGE_LEN)
    if len(ciphertext) == 0:
        # Connection was closed
        raise Exception("Unexpected close")
        
    aes_data =  key_data["client_aes_data"]
    raw = decrypt_msg(ciphertext, aes_data["key"], aes_data["iv"])

    data = json.loads(raw)
    message = data["message"]

    hash = bytes.fromhex(data["hmac"])
    # verify the hmac of the message
    if verify_signed_message(
            message.encode('utf-8'), 
            hash, 
            key_data["shared_key"]
        ) == False:
        raise Exception("Message hmac is not valid!")

    if data["type"] == "message":
        # store the new IV, so the next message from this client can be 
        # decrypted
        aes_data["iv"] = bytes.fromhex(data["new_iv"])
        return message
    elif data["type"] == "close":
        # the other end wants to close the connection, so they sent a
        # special close message, we need to respond.
        handle_close_message(conn, data, key_data)
        raise Exception("Closed connection")
    else:
        raise Exception(f"Unkown message type \"{data['type']}\"")

def close(conn, key_data):
    # when closing the connection we want to verify that the other end knows
    # that we want to close the connection. This is done by sending a message
    # of type "close" with some random data. The client sends this random data
    # back and then we can be sure that they know the connection will be closed.
    random_data = os.urandom(32).hex()

    data = build_message_header("close", random_data, key_data)
    raw = json.dumps(data)

    aes_data =  key_data["own_aes_data"]
    ciphertext = encrypt_msg(raw, aes_data["key"], aes_data["iv"])
    conn.send(ciphertext)

    try:
        client_aes_data =  key_data["client_aes_data"]
        ciphertext = conn.recv(settings.MAX_MESSAGE_LEN)
        # verify the received data
        raw = decrypt_msg(ciphertext, client_aes_data["key"], 
            client_aes_data["iv"])

        ack_data = json.loads(raw)
        message = data["message"]

        hash = bytes.fromhex(ack_data["hmac"])
        if verify_signed_message(
            message.encode('utf-8'), 
            hash, 
            key_data["shared_key"]
        ) == False:
            raise Exception("Close message hmac is not valid!")
        
        if message != random_data:
            raise Exception("Close message has not been confirmed by peer")
    except Exception as e:
        raise Exception("Close message was not received")

    # it's verified that the client has received closed message 
    # so the connection can be closed
    conn.close()

# when a `close` message is received the message is bounced back and the
# connection will be closed
def handle_close_message(conn, data, key_data):
    random_data = data["message"]

    data = build_message_header("close", random_data, key_data)
    raw = json.dumps(data)

    aes_data =  key_data["own_aes_data"]
    ciphertext = encrypt_msg(raw, aes_data["key"], aes_data["iv"])

    conn.send(ciphertext)
    conn.close()

########## Handshake Functions ##########
# the functions `do_server_handshake` and `do_client_handshake` are the
# `accept` functions. The program that wants to connect first is considered
# the "client".
    
def get_key_pair():
    # generate keys if public or private key is not set. Else load the keys
    # specified in the settings file
    if settings.PUBLIC_KEY is None or settings.PRIVATE_KEY is None:
        private_key = ec.generate_private_key(
            settings.ELLIPTIC_CURVE()
        )
        public_key = private_key.public_key()

        # encode public key into PEM format
        serialized = public_key.public_bytes(serialization.Encoding.PEM, 
            serialization.PublicFormat.SubjectPublicKeyInfo)
        
        util.print_message('[INFO]: Generated public key:')
        util.print_message(serialized.decode('ascii'))
        return (private_key, public_key, serialized)
    else:
        # read public and private key files as binary data
        public_key_bytes = b''
        with open(settings.PUBLIC_KEY, "rb") as f:
            public_key_bytes = f.read()

        private_key_bytes = b''
        with open(settings.PRIVATE_KEY, "rb") as f:
            private_key_bytes = f.read()

        # load the keys from PEM format
        private_key = serialization.load_pem_private_key(
            private_key_bytes, password=settings.KEY_PASSWORD)
        public_key = serialization.load_pem_public_key(
            public_key_bytes)
        
        return (private_key, public_key, public_key_bytes)

# Act as a server during the handshake
def do_server_handshake(conn, addr, name):
    (private_key, public_key, public_key_bytes) = get_key_pair()
    
    # receive client preferences
    client_preferences_data = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    client_config = json.loads(client_preferences_data)
    peer_name = client_config["name"]
    util.print_message(f"[INFO]: Connection identifies itself "\
        f"as \"{peer_name}\"")
    # receive clients public key
    client_public_key_bytes = conn.recv(client_config['public_key_len'])
    # load public key from PEM format
    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes)
        
    util.print_message("[INFO]: Peer public key:")
    util.print_message(client_public_key_bytes.decode('ascii'))

    # get the shared key and derive a new key from the shared key
    shared_key = private_key.exchange(
        ec.ECDH(), client_public_key
    )    
    derived_key = HKDF(
        algorithm=settings.HASH_ALGORITHM(),
        length=32,
        info=b'shared key',
        salt=None
    ).derive(shared_key)

    # pick the strongest algorithm that the client supports
    algorithm = util.pick_algorithm(settings.VALID_SYMMETRIC_ALGORITHMS, 
        client_config)
    if algorithm is None:
        # the client doesn't support any of the algorithms we define as strong
        raise Exception("Client sent weak/invalid algorithms")
    if algorithm != 'AES-256-CBC':
        raise Exception("\nClient supports " \
                        f"\"{client_config['supported_algorithms']}\". But "\
                        "Only AES-256-CBC is implemented!")
    
    util.print_message(f"[INFO]: Picked algorithm {algorithm} as symmetric " \
                       "encryption algorithm")

    # let the client know which algorithm we picked and send our public key
    header = util.create_algorithm_header_server(algorithm, 
        len(public_key_bytes), name)
    util.print_message('before send')
    conn.send(header)
    conn.send(public_key_bytes)

    # sign all the data received from the client with the derived key.
    # the client can validate that each message that it send
    # is unchanged.
    handshake_data = client_preferences_data + client_public_key_bytes
    signed_handshake = sign_message(handshake_data, derived_key)
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
        
    util.print_message(f"[INFO]: Handshake verified! Further communication " \
        f"with peer {addr[0]}:{addr[1]} is now encrypted with {algorithm}")
    
    (server_aes_keys, client_aes_keys) = derive_symmetric_keys_from_shared_key(shared_key)
    key_data = {
        "shared_key": shared_key,
        "client_public_key": client_public_key,
        "client_public_key_pem": client_public_key_bytes,
        "own_public_key": public_key,
        "own_public_key_pem": public_key_bytes,
        "own_private_key": private_key,
        "client_aes_data": client_aes_keys,
        "own_aes_data": server_aes_keys
    }

    return (peer_name, key_data)

# Act as a client during the handshake
def do_client_handshake(conn, name):
    (private_key, public_key, public_key_bytes) = get_key_pair()

    # create header containing which algorithms the client supports and
    # how long the send public key is.
    header = util.create_algorithm_header_client(
        settings.VALID_SYMMETRIC_ALGORITHMS, 
        len(public_key_bytes), name)
    conn.send(header)
    conn.send(public_key_bytes)

    # receive symmetric algorithm and public key len from the server
    server_choices_data = conn.recv(settings.HANDHSAKE_HEADER_LEN)
    server_config = json.loads(server_choices_data)
    peer_name = server_config["name"]

    print(f"[INFO]: Connection identifies itself as \"{peer_name}\"")
    # verify chosen key from server
    algorithm = server_config['algorithm']
    if algorithm not in settings.VALID_SYMMETRIC_ALGORITHMS:
        raise Exception("server picked unsupported algorithm")

    
    print(f"[INFO]: {peer_name} picked {algorithm} as symmetric " \
          "encryption algorithm")
    # receive the servers public key
    server_public_key_bytes = conn.recv(server_config['public_key_len'])
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes)
    
    util.print_message("[INFO]: Peer public key:")
    util.print_message(server_public_key_bytes.decode('ascii'))

    # get the shared key and derive a new key from the shared key
    shared_key = private_key.exchange(
        ec.ECDH(), server_public_key
    )    
    derived_key = HKDF(
        algorithm=settings.HASH_ALGORITHM(),
        length=32,
        info=b'shared key',
        salt=None
    ).derive(shared_key)

    # sign all the data received from the server with the derived key.
    # the server can validate that each message that it send
    # is unchanged.
    handshake_data = server_choices_data + server_public_key_bytes
    signed_handshake = sign_message(handshake_data, derived_key)
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
    
    (server_aes_keys, client_aes_keys) = derive_symmetric_keys_from_shared_key(
        shared_key)

    key_data = {
        "shared_key": shared_key,
        "own_public_key": public_key,
        "own_public_key_pem": public_key_bytes,
        "own_private_key": private_key,
        "client_public_key": server_public_key,
        "client_public_key_pem": server_public_key_bytes,
        "client_aes_data": server_aes_keys,
        "own_aes_data": client_aes_keys,
    }

    return (peer_name, key_data)

### Encryption utilities ###

# sign `message` with `key`, returns bytes 
def sign_message(message, key):
    h = hmac.HMAC(key, settings.HASH_ALGORITHM())
    h.update(message)
    return h.finalize()

# verify `message` with `key`, returns the result as a boolean 
def verify_signed_message(message, hash, key):
    h = hmac.HMAC(key, settings.HASH_ALGORITHM())
    h.update(message)

    try:
        h.verify(hash)
        return True
    except exceptions.InvalidSignature:
        # the hmac isn't valid!
        return False

# expand the `key` and derive two keys and two initalization vectors
def derive_symmetric_keys_from_shared_key(key):
    # expand the shared key to 96 bits. We split up these key into 4 parts:
    # two 32 bits keys and two 16 bits initialization vectors for AES
    hkdf = HKDFExpand(
        algorithm=settings.HASH_ALGORITHM(),
        length=96,
        info=b'expanded key from ECDH'
    )
    key = hkdf.derive(key)
   
    return ({
        "key": key[:32],
        "iv": key[32:48]
    }, {
        "key": key[48:80],
        "iv": key[80:96]
    })

# encrypt `msg` using AES256 with `key` and `iv`
def encrypt_msg(msg, key, iv):
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # create padder to make the msg divisible by the block length of AES-256
    padder = padding.PKCS7(algorithms.AES256.block_size).padder()
    padded_msg = padder.update(msg.encode('utf-8')) + padder.finalize()

    # encrypt the padded message using our cipher
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext

# encrypt `msg` using AES256 with `key` and `iv`
def decrypt_msg(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # decrypt the ciphertext to get a padded version of the message
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()

    # unpad the decrypted ciphertext to get the message
    msg = unpadder.update(padded_msg) + unpadder.finalize()
    return msg.decode('utf-8')