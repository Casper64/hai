import json
import settings
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def create_algorithm_header_client(supported_algorithms, public_key_len):
    header = {
        'supported_algorithms': supported_algorithms,
        'public_key_len': public_key_len
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")

    # add padding, so the message is the correct length
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

def create_algorithm_header_server(picked_algorithm, public_key_len):
    header = {
        'algorithm': picked_algorithm,
        'public_key_len': public_key_len
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")
    
    # add padding, so the message is the correct length
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

# pick the strongest algorithm from the clients configuration
def pick_algorithm(strong_algorithms, client_config):
    client_algorithms = client_config['supported_algorithms']
    for alg in strong_algorithms:
        if alg in client_algorithms:
            return alg
        
    return None

def get_cipher_by_name(name):
    if name == "AES-256":
        return Cipher(algorithms.AES())

def sign_message(message, key):
    h = hmac.HMAC(key, settings.HASH_ALGORITHM())
    h.update(message)
    return h.finalize()

def derive_symmetric_keys_from_shared_key(key):
    # expand the shared key to 96 bits. We split up these key into 4 parts:
    # two 32 bits keys and two 16 bits initialization vectors for AES
    hkdf = HKDFExpand(
        algorithm=settings.HASH_ALGORITHM(),
        length=2 * 32 + 2 * 16,
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

# encrypt `msg`` with the Cipher instance `cipher`
def encrypt_msg(msg, cipher):
    encryptor = cipher.encryptor()
    # create padder to make the msg divisible by the block length of AES-256
    padder = padding.PKCS7(algorithms.AES256.block_size).padder()
    # encode with utf-8
    padded_msg = padder.update(msg.encode('utf-8')) + padder.finalize()

    # encrypt the padded message using our cipher
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext

def decrypt_msg(ciphertext, cipher):
    decryptor = cipher.decryptor()
    # decrypt the ciphertext to get a padded version of the message
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
    # unpad the decrypted ciphertext to get the message
    msg = unpadder.update(padded_msg) + unpadder.finalize()
    # decode with utf-8
    return msg.decode('utf-8')

# print a message from a peer and keep the current cursor position
def print_peer_message(msg, peer_name):
    print(
                "\u001B[s"             # Save current cursor position
                "\u001B[A"             # Move cursor up one line
                "\u001B[999D"          # Move cursor to beginning of line
                "\u001B[S"             # Scroll up/pan window down 1 line
                "\u001B[L",            # Insert new line
    end="")     
    print(f"{peer_name}: {msg}", end="")
    print("\u001B[u", end="")  # Move back to the former cursor position
    print("", end="", flush=True)  # Flush message
