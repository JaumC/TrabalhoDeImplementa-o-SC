from aes_constants import S_BOX, RCON

def hex_string_to_bytes(hex_string):
    # Verifique se hex_string é uma string hexadecimal
    if isinstance(hex_string, bytes):
        hex_string = hex_string.hex()  # Converte bytes para uma string hexadecimal

    # Certifique-se de que a string é hexadecimal e tem comprimento par
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have an even length")
    
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


def CTR(counter):
    # Se counter for bytes, converta para string hexadecimal
    if isinstance(counter, bytes):
        counter = counter.hex()

    counter_bytes = hex_string_to_bytes(counter)

    # Incrementa o contador
    for i in reversed(range(len(counter_bytes))):
        if counter_bytes[i] != 255:
            counter_bytes[i] += 1
            break
        counter_bytes[i] = 0

    # Converte a lista de bytes de volta para uma string hexadecimal
    return ''.join(f'{byte:02x}' for byte in counter_bytes).upper()




#Multiplicação de dois elementos no campo finito GF
def gmul(a, b):
    p = 0

    for _ in range(8):
        if b & 1:
            p ^= a
        
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    
    return p & 0xFF

def pad_key(key, length=16):
    return key + [0] * (length - len(key))

#Derivação da key em subkeys para as rodadas de cifração
def keyExpansion(key):
    key = pad_key(key)
    expanded_key = [0] * 176

    # Separa e adiciona as partes da chave de 16 em 16
    for i in range(16):
        expanded_key[i] = key[i]

    # Começa do valor 17° até o 176, saltando de 4 em 4
    for j in range(16, 176, 4):
        last_bytes = expanded_key[j-4:j]
        
        # Rotação e aplicação do SBOX
        if j % 16 == 0:
            last_bytes = last_bytes[1:] + last_bytes[:1]
            
            last_bytes = [S_BOX[b] for b in last_bytes]

            last_bytes[0] ^= RCON[j // 16 - 1]

        for l in range(4):
            expanded_key[j + l] = expanded_key[j - 16 + l] ^ last_bytes[l]

    return expanded_key

#Aplicação das chaves de rodada para cada bloco do state
def addRoundKey(state, roundKey):
    if isinstance(roundKey, list) and all(isinstance(i, int) for i in roundKey):
        roundKey = [list(roundKey[i:i+4]) for i in range(0, len(roundKey), 4)]

    # Aplica a operação XOR em cada byte do estado
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundKey[i][j]
    return state


def to_hex_string(data):
    if isinstance(data[0], list): 
        return ' | '.join(' '.join(f'{x:02x}' for x in row) for row in data)
    else: 
        return ' '.join(f'{x:02x}' for x in data)