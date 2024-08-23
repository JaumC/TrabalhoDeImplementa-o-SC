from aes_constants import S_BOX, RCON


def CTR(counter):
    for i in reversed(range(len(counter))):
        if counter[i] != 255:
            counter[i] += 1
            break
        counter[i] = 0
    return counter


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


#Derivação da key em subkeys para as rodadas de cifração
def keyExpansion(key):
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
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundKey[i * 4 + j]
    return state


def to_hex_string(data):
    if isinstance(data[0], list): 
        return ' | '.join(' '.join(f'{x:02x}' for x in row) for row in data)
    else: 
        return ' '.join(f'{x:02x}' for x in data)