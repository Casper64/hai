import json
import settings
from cryptography.hazmat.primitives import hashes, hmac
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

def derive_symmetric_keys_from_shared_key(key, algorithm_fn):
    # expand the shared key to 96 bits. We split up these key into 4 parts:
    # two 32 bits keys and two 16 bits initialization vectors for AES
    hkdf = HKDFExpand(
        algorithm=settings.HASH_ALGORITHM(),
        length=2 * 32 + 2 * 16,
        info=None
    )
    key = hkdf.derive(key)
   
    return ({
        "key": key[:32],
        "iv": key[32:48]
    }, {
        "key": key[48:80],
        "iv": key[80:96]
    })