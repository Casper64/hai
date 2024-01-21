# Readme

The 100% console based secure messaging program.

## Informatie
Alle encryptie methodes: send, recv, close en accept staan in `hai_core.py`.
De rest van de code is voor de console app.

Het programma is beide een client en een server. Het programma dat als eerste
een connectie aangaat wordt beschouwd als "client" tijdens de handshake.

Alleen de `cryptography` module is nodig om het programma te runnen.
Zie https://cryptography.io/

## Gebruik 

Dit programma is getest in python `3.11.6` en kan op de volgende manier
gebruikt worden:
```bash
python3 hai.py
```

## Settings
In het bestand `settings.py` kunnen een paar instellingen van het progamma
worden aangepast. 

## Key generation

Encryptie keys worden automatisch gegenereerd, maar er kan ook gebruik
gemaakt worden van zelfgegenereerde keys door gebruik te maken van het
`create_keys.sh` script.

```bash
chmod +x create_keys.sh
./create_keys.sh
```

Daarna moeten de `PRIVATE_KEY` en `PUBLIC_KEY` instellingen worden aangepast
in `settings.py`.

> **Note:**
> Keys moeten in PEM formaat zijn en gebruik maken van een elliptische curve