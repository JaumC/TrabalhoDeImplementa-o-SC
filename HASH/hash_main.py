from sympy import isprime, mod_inverse
import hashlib
import random
import base64
import os


def hash_message(msg):
    return hashlib.sha3_256(msg).digest()


def largePrime(bits):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num


def genRSA(bits=1024):
    p = largePrime(bits)
    q = largePrime(bits)
    n = p * q
    phi = (p-1) * (q - 1)

    e = 65537
    d = mod_inverse(e, phi)

    pubKey = (e, n)
    privKey = (d, n)

    return pubKey, privKey

def oaep_pad(msg, n):
    k = (n.bit_length() + 7) // 8
    l = hashlib.sha3_256(b'').digest()
    hlen = len(l)

    # Padding
    ps = b'\x00' * (k - len(l) - len(msg) - 2)
    db = ps + b'\x01' + msg
    db_mask = os.urandom(len(db))
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed = os.urandom(hlen)
    masked_seed = bytes(x ^ y for x, y in zip(seed, masked_db[:hlen]))

    return masked_seed + masked_db[hlen:]

def oaep_unpad(padded, n):
    k = (n.bit_length() + 7) // 8
    l = hashlib.sha3_256(b'').digest()
    hlen = len(l)

    masked_seed = padded[:hlen]
    masked_db = padded[hlen:]
    seed = os.urandom(hlen)
    db_mask = bytes(x ^ y for x, y in zip(masked_seed, seed))
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    # Remove padding
    pos = db.find(b'\x01')
    if pos == -1:
        raise ValueError("Invalid padding")
    return db[pos + 1:]

def verifying(pubKEY, msg, signOn64):
    signature = base64.b64decode(signOn64)
    cipherInt = int.from_bytes(signature, byteorder='big')
    decryptHASH = decryptRSA(pubKEY, cipherInt)
    msgHASH = hash_message(msg)
    return decryptHASH == msgHASH


def signMSG(privKEY, msg):
    hashMSG = hash_message(msg)
    signature = encryptRSA(privKEY, hashMSG)
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    signOn64 = base64.b64encode(signature_bytes).decode('utf-8')
    return signOn64


def encryptRSA(pubKEY, plaintext):
    e, n = pubKEY
    plaintext = oaep_pad(plaintext, n)
    plaintextInt = int.from_bytes(plaintext, byteorder='big')
    ciphertext = pow(plaintextInt, e, n)
    return ciphertext


def decryptRSA(privKEY, ciphertext):
    d, n = privKEY
    cipherInt = pow(ciphertext, d, n) 
    plaintext = cipherInt.to_bytes((cipherInt.bit_length() + 7) // 8, byteorder='big')
    return oaep_unpad(plaintext, n)


pubKey, privKey = genRSA(1024)
print("Public Key:", pubKey)
print("Private Key:", privKey)

message = 'Esta é uma mensagem secreta.'.encode('utf-8')
signature = signMSG(privKey, message)

is_valid = verifying(pubKey, message, signature)
print(f"Assinatura válida: {is_valid}")