from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# on which host to bind the socket. Change this to `localhost` if you don't 
# want to accept outside connections.
HOST="0.0.0.0"

HASH_ALGORITHM = hashes.SHA256
HANDHSAKE_HEADER_LEN = 512
MAX_MESSAGE_LEN = 1024

# if the public and private key options are None, a new key pair is generated
# for each new connection. Else the given keys will be loaded.
# Keys should be encoded in PEM format and use an elliptic curve
PRIVATE_KEY = None
PUBLIC_KEY = None
# PRIVATE_KEY = "keys/private-key.pem"
# PUBLIC_KEY = "keys/public-key.pem"

# set this if the private key has a password
KEY_PASSWORD = None

# use NIST P-521 elliptic curve. These curves are faster and smaller than
# regular RSA or DSA. The cryptography module only supports NIST curves
# and unfortunately none are considered "safe", so we take the curve with
# the biggest prime that is available to us.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves
ELLIPTIC_CURVE = ec.SECP521R1

# This array will be sent to the other program. You can add other algorithms,
# but currently only AES-256 in CBC mode is implemented so it won't do anything.
VALID_SYMMETRIC_ALGORITHMS = ['AES-256-CBC']