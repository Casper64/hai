from cryptography.hazmat.primitives import serialization, hashes, hmac

HASH_ALGORITHM = hashes.SHA256
HANDHSAKE_HEADER_LEN = 512