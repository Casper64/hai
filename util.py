import json
import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

def create_header_client(supported_algorithms, public_key_len):
    header = {
        'supported_algorithms': supported_algorithms,
        'public_key_len': public_key_len
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")
    
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

def create_header_server(picked_algorithm, public_key_len):
    header = {
        'algorithm': picked_algorithm,
        'public_key_len': public_key_len
    }

    data = json.dumps(header)
    data = data.encode()
    if len(data) > settings.HANDHSAKE_HEADER_LEN:
        raise Exception("header is too long!")
    
    return data.ljust(settings.HANDHSAKE_HEADER_LEN)

def pick_algorithm(supported_algorithms, client_config):
    client_algorithms = client_config['supported_algorithms']
    for alg in supported_algorithms:
        if alg in client_algorithms:
            return alg
        
    return None

def sign_message(message, key):
    h = hmac.HMAC(key, settings.HASH_ALGORITHM())
    h.update(message)
    return h.finalize()