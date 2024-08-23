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

def mgf1(seed, length, hash_func=hashlib.sha3_256):
    hlen = len(hash_func(b'').digest())
    output = b''
    for i in range(0, (length + hlen - 1) // hlen):
        c = (i).to_bytes(4, byteorder='big')
        output += hash_func(seed + c).digest()

    return output[:length]

def oaep_pad(msg, n, hash_func=hashlib.sha3_256):
    k = (n.bit_length() + 7) // 8
    l = hash_func(b'').digest()
    hlen = len(l)

    ps = b'\x00' * (k - len(l) - len(msg) - 2 * hlen - 2)
    db = l + ps + b'\x01' + msg

    seed = os.urandom(hlen)
    
    db_mask = mgf1(seed, len(db), hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    
    seed_mask = mgf1(masked_db, hlen, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return masked_seed + masked_db

def oaep_unpad(padded, n, hash_func=hashlib.sha3_256):
    k = (n.bit_length() + 7) // 8
    l = hash_func(b'').digest()
    hlen = len(l)

    masked_seed = padded[:hlen]
    masked_db = padded[hlen:]

    seed_mask = mgf1(masked_db, hlen, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, len(masked_db), hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash = db[:hlen]
    if l_hash != l:
        raise ValueError('Padding inválido: hash mismatch')
    
    db = db[hlen:]
    pos = db.find(b'\x01')
    if pos == -1:
        raise ValueError("Padding inválido: no delimiter")
    
    return db[pos + 1:]

def encryptRSA(pubKEY, plaintext):
    e, n = pubKEY
    padded_plaintext = oaep_pad(plaintext, n)
    plaintextInt = int.from_bytes(padded_plaintext, byteorder='big')
    ciphertext = pow(plaintextInt, e, n)
    return ciphertext

def decryptRSA(privKEY, ciphertext):
    d, n = privKEY
    cipherInt = pow(ciphertext, d, n) 
    plaintext = cipherInt.to_bytes((cipherInt.bit_length() + 7) // 8, byteorder='big')
    return oaep_unpad(plaintext, n)

def signMSG(privKEY, msg):
    hashMSG = hash_message(msg)
    signature = encryptRSA(privKEY, hashMSG)
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    signOn64 = base64.b64encode(signature_bytes).decode('utf-8')
    return signOn64

def verifying(pubKEY, msg, signOn64):
    signature = base64.b64decode(signOn64)
    cipherInt = int.from_bytes(signature, byteorder='big')
    decryptHASH = decryptRSA(pubKEY, cipherInt)
    msgHASH = hash_message(msg)
    return decryptHASH == msgHASH


pubKey, privKey = genRSA(1024)
print("Public Key:", pubKey)
print("Private Key:", privKey)

# Mensagem de teste
message = 'Esta é uma mensagem secreta.'.encode('utf-8')

# Assinatura da mensagem
signature = signMSG(privKey, message)
print(f"Signature: {signature}")

# Verificação da assinatura
is_valid = verifying(pubKey, message, signature)
print(f"Assinatura válida: {is_valid}")