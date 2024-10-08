from aes_constants import S_BOX, RCON
from PIL import Image
import io

#Percorre o state e substitui cada valor pelo correspondente em SBOX
def subBytes(state): 
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state


#Alteração da posição dos bytes nas linhas 1, 2 e 3 da matriz
def shiftRows(state): 
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

    return state


#Multiplicação das colunas da matriz no campo finito GF
def mixColumns(state):
    newState = [[0] * 4 for _ in range(4)]

    for c in range(4):
        newState[0][c] = gmul(0x02, state[0][c]) ^ gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
        newState[1][c] = state[0][c] ^ gmul(0x02, state[1][c]) ^ gmul(0x03, state[2][c]) ^ state[3][c]
        newState[2][c] = state[0][c] ^ state[1][c] ^ gmul(0x02, state[2][c]) ^ gmul(0x03, state[3][c])
        newState[3][c] = gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ gmul(0x02, state[3][c])

    for i in range(4):
        for j in range(4):
            state[i][j] = newState[i][j]

    return newState


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
def keyExpansion(key, rounds):
    if rounds == 10:
        key_size = 16
        key_len = 176

    elif rounds == 12:
        key_size = 24
        key_len = 208

    elif rounds == 14:
        key_size = 32
        key_len = 240

    else:
        print('\nTamanho de rounds inválido, deve ser[10, 12, 14]')
        return
    
    expanded_key = [0] * key_len

    # Separa e adiciona as partes da chave de 16 em 16
    for i in range(key_size):
        expanded_key[i] = key[i]

    # Começa do valor 17° até o 176, saltando de 4 em 4
    for j in range(key_size, key_len, 4):
        last_bytes = expanded_key[j-4:j]
        
        # Rotação e aplicação do SBOX
        if j % key_size == 0:
            last_bytes = last_bytes[1:] + last_bytes[:1]
            
            last_bytes = [S_BOX[b] for b in last_bytes]

            last_bytes[0] ^= RCON[j // key_size - 1]
        
        elif key_size > 24 and j % key_size == 16:
            last_bytes = [S_BOX[b] for b in last_bytes]

        for l in range(4):
            expanded_key[j + l] = expanded_key[j - key_size + l] ^ last_bytes[l]

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


def bytes_to_state(block):
    return [list(block[i:i+4]) for i in range(0, len(block), 4)]


def state_to_bytes(state):
    return bytes([item for sublist in state for item in sublist])


def image_to_bytes(image):
    with Image.open(image) as img:
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_bytes = img_byte_arr.getvalue()
    return img_bytes


def bytes_to_image(image, path):
    img_byte_arr = io.BytesIO(image)
    with Image.open(img_byte_arr) as img:
        img.save(path)