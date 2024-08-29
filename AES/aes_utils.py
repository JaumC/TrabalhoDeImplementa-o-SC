from aes_constants import S_BOX, RCON

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