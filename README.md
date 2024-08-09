# Readme

The 100% console based messaging program using the `cryptography` library in python; a project I made for my cryptograpghy course.

This code is probably not 100% secure, please only use it for educational purposes.

All the core functionality of the program are in `hai_core.py`

## Features

- Console based
- Supports multiple chats at the same time (using non-blocking sockets)
- Custom handshake based on TLS 
- Supports elliptic curve keys
- Hmac validates messages (iv's are never reused)
- Error messages for invalid / unvalidates messages

> **Note**:
> Public key verification using a CA not implemented.

## Quick Start

This program was developed and tested using python `3.11.6`.

Make a new virtual environment and instal the required packages
```bash
python3 -m venv venv
. ./venv/bin/activate
pip install -r requirements.txt
```

Then start the program in `hai.py`.
```bash
python3 hai.py
```

## Settings

You can configure the program in `hai.py`.

## Key generation

Keys will be automatically generated. You can generate your own keys using
the `create_keys.sh` program.
```bash
chmod +x create_keys.sh
./create_keys.sh
```

Then change the `PRIVATE_KEY` and `PUBLIC_KEY` settings in `settings.py`.

> **Note:**
> Keys have to be encoded in PEM format and use an elliptic curve.
