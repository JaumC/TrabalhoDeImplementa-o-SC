# RSA Hash com OAEP

from sympy import mod_inverse
import hashlib
import random
import base64
import os



def calc_hash(msg):
    return hashlib.sha3_256(msg).digest()

# Baseado em https://gist.github.com/KaiSmith/5886940
def miller_rabin(n, k=100):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        possibly_prime = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                possibly_prime = True
                break
        if not possibly_prime:
            return False
    return True


# Geração de um número primo grande
def largePrime(bits):
    while True:
        # Gera até encontrar um numero primo
        num = random.getrandbits(bits)
        num |= (1 << (bits-1)) | 1
        if miller_rabin(num):
            return num


# Criação da chave pública e privada
def genRSA(bits=1024):
    p = largePrime(bits)
    q = largePrime(bits)
    n = p * q
    phi = (p-1) * (q - 1)

    # Valor comum para RSA
    e = 65537

    d = mod_inverse(e, phi)

    pubKey = (e, n)
    privKey = (d, n)

    return pubKey, privKey


# Criação da máscara para os dados
def mgf1(seed, tam, hash_func=hashlib.sha3_256):
    hlen = len(hash_func(b'').digest())
    output = b''
    
    for i in range(0, (tam + hlen - 1) // hlen):

        # Geração de blocos das máscaras
        c = (i).to_bytes(4, byteorder='big')
        output += hash_func(seed + c).digest()

    return output[:tam]


# Aplicação do padding OAEP
def oaep_pad(msg, n, hash_func=hashlib.sha3_256):
    # Calcula o comprimento total de bytes necessários
    k = (n.bit_length() + 7) // 8

    l = hash_func(b'').digest()
    hlen = len(l)

    # Padding string com bytes \x00
    ps = b'\x00' * (k - len(l) - len(msg) - 2 * hlen - 2)
    db = l + ps + b'\x01' + msg

    seed = os.urandom(hlen)
    
    # Gerando seed
    db_mask = mgf1(seed, len(db), hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    
    seed_mask = mgf1(masked_db, hlen, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return masked_seed + masked_db


# Remoção do padding OAEP
def oaep_unpad(padded, n, hash_func=hashlib.sha3_256):
    k = (n.bit_length() + 7) // 8
    l = hash_func(b'').digest()
    hlen = len(l)

    # Extração da seed
    masked_seed = padded[:hlen]
    masked_db = padded[hlen:]

    # Revertendo a máscara
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

    # Aplicação do oaep antes da cifração
    padded_plaintext = oaep_pad(plaintext, n)
    plaintextInt = int.from_bytes(padded_plaintext, byteorder='big')

    ciphertext = pow(plaintextInt, e, n)
    return ciphertext


def decryptRSA(privKEY, ciphertext):
    d, n = privKEY

    # Decifração do texto
    cipherInt = pow(ciphertext, d, n) 
    plaintext = cipherInt.to_bytes((cipherInt.bit_length() + 7) // 8, byteorder='big')

    # Remoção do oaep padding
    return oaep_unpad(plaintext, n)


# Assinatura de mensagem
def signMSG(privKEY, msg):
    hashMSG = calc_hash(msg)

    signature = encryptRSA(privKEY, hashMSG)
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')

    # Assinatura codificada em BASE64
    signOn64 = base64.b64encode(signature_bytes).decode('utf-8')

    return signOn64


# Verificador de assinaturas
def verifying(pubKEY, msg, signOn64):

    # Decodificação da assinatura em BASE64
    signature = base64.b64decode(signOn64)

    cipherInt = int.from_bytes(signature, byteorder='big')
    decryptHASH = decryptRSA(pubKEY, cipherInt)

    msgHASH = calc_hash(msg)

    # Deve retornar True se decrypt e msg coincidirem
    return decryptHASH == msgHASH




pubKey, privKey = genRSA(1024)
print("\nPublic Key:\n", pubKey)
print()
print("Private Key:\n", privKey)
print()

# Mensagem de teste
message = 'Esta é uma mensagem secreta.'.encode('utf-8')
print(message, '\n')

# Assinatura da mensagem
signature = signMSG(privKey, message)
print(f"Signature: {signature}\n")

# Verificação da assinatura
is_valid = verifying(pubKey, message, signature)
print(f"Assinatura válida: {is_valid}")