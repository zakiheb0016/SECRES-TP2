# Project Overview

This Python script processes an RSA public key in base64 format to extract the public exponent `e` and the modulus `n`. From the modulus `n`, it derives the prime factors `p` and `q`, where `n = p * q`, with `p > q` and both `p` and `q` being prime numbers. Using these values, the script calculates the private key `(d, n)`, which it then saves in both DER format and a plain text file following the ASN.1 structure.

The private key is subsequently used to decrypt a file containing a password (passphrase). This passphrase is transformed into a 256-bit AES key for AES-256-CBC encryption. The transformation utilizes the `md5` hash function without a salt.

## Project Requirements

Before running the script, ensure you have the following:

- **OpenSSL**
  - If not already installed, use the following command to install it:
    ```bash
    sudo apt install openssl
    ```

- **Cryptography Package in Python**
  - If not already installed, use one of the following commands to install it:
    ```bash
    pip install cryptography
    ```
    or
    ```bash
    sudo apt install python3-cryptography