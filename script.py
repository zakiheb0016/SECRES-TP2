import os
import math
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, math.isqrt(num) + 1):
        if num % i == 0:
            return False
    return True

def factorize_n(n):
    for i in range(2, math.isqrt(n) + 1):
        if is_prime(i):
            if n % i == 0:
                q = i
                p = n // i
                return p, q
    return None, None  

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key_data = key_file.read()
    return serialization.load_pem_public_key(public_key_data)

def calculate_private_key(n, e, p, q):
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    iqmp = pow(q, -1, p)
    e1 = d % (p - 1)
    e2 = d % (q - 1)
    public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=e1,
        dmq1=e2,
        iqmp=iqmp,
        public_numbers=public_numbers
    ).private_key()
    return private_key, d, e1, e2, iqmp

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def save_private_key(private_key_der, filename):
    with open(filename, "wb") as private_key_file:
        private_key_file.write(private_key_der)

def save_private_key_info(n, e, d, p, q, e1, e2, iqmp, filename):
    private_key_info = f"""
asn1=SEQUENCE:rsa_key [rsa_key]
version=INTEGER:0
modulus=INTEGER:{n}
pubExp=INTEGER:{e}
privExp=INTEGER:{d}
p=INTEGER:{p}
q=INTEGER:{q}
e1=INTEGER:{e1}
e2=INTEGER:{e2}
coeff=INTEGER:{iqmp}
"""
    with open(filename, "w") as private_file:
        private_file.write(private_key_info)

def decrypt_using_openssl():
    os.system("openssl rsautl -decrypt -inkey PrivateKey.der -in cipher.txt -out pass.txt > /dev/null 2>&1")

def read_decrypted_password(filename):
    with open(filename, "r") as pass_file:
        return pass_file.read().strip()

def decrypt_aes_message(passphrase):
    os.system(f"openssl enc -d -aes-256-cbc -in MessageCipher.txt -out DecryptedMessage.txt -k {passphrase} -nosalt -md md5 > /dev/null 2>&1")

def main():
    public_key = load_public_key("PublicKey.txt")
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e
    p, q = factorize_n(n)
    
    print(f"Modulus (n): {n}")
    print(f"Found primes: p = {p}, q = {q}")
    
    private_key, d, e1, e2, iqmp = calculate_private_key(n, e, p, q)
    private_key_der = serialize_private_key(private_key)
    save_private_key(private_key_der, "PrivateKey.der")
    
    print("Private key has been saved in DER format to 'PrivateKey.der'.")
    save_private_key_info(n, e, d, p, q, e1, e2, iqmp, "Private.txt")
    
    decrypt_using_openssl()
    passphrase = read_decrypted_password("pass.txt")
    decrypt_aes_message(passphrase)

    print("The file DecryptedMessage.txt contains the decrypted message")

if __name__ == "__main__":
    main()
