from functools import reduce
from aes_constants import S_BOX
from aes_utils import addRoundKey, gmul, keyExpansion



#Percorre o state e substitui cada valor pelo correspondente em SBOX
def subBytes(state): #CHECKED
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state


#Alteração da posição dos bytes nas linhas 1, 2 e 3 da matriz
def shiftRows(state): #CHECKED
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


def encryptAES(plaintext, key, nonce):
    rounds = int(input('Digite a quantidade de rounds[10, 12 ou 14]: '))
    expanded_key = keyExpansion(key)
    counter = nonce

    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)] 

    cipherBlocks = []

    for block in blocks:
        if len(block) < 16:
            block = block + bytes(16-len(block))

        state = [counter[i:i+4] for i in range(0, len(counter), 4)]            
        state = addRoundKey(state, expanded_key[16:])

        for round in range(rounds - 1):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, expanded_key[(round + 1) * 16:(round + 2) * 16])

        state = subBytes(state)
        state = shiftRows(state)
        state = addRoundKey(state, expanded_key[rounds * 16:])

        # Concatena as colunas em uma lista
        encrypted_counter = reduce(lambda x, y: x + y, state)

        # XOR
        cipherBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        cipherBlocks.append(cipherBlock)

        counter = CTR(counter)

    ciphertext = b''.join(cipherBlocks)

    return ciphertext, rounds