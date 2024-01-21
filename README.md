# Readme

The 100% console based secure messaging program.

Alle encryptie methodes: send, recv, close en accept staan in `hai_core.py`.
De rest van de code is voor de console app.

## Quick Start

This program was tested using python `3.11.6`.

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
