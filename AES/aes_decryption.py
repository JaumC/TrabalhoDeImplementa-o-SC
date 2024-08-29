from functools import reduce
from aes_constants import INV_S_BOX
from aes_utils import addRoundKey
from aes_utils import gmul, keyExpansion
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

#Percorre o state e substitui cada valor pelo correspondente em INV_SBOX
def invSubBytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]
    return state


#Alteração da posição dos bytes nas linhas 1, 2 e 3 da matriz
def invShiftRows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

    return state


#Multiplicação das colunas da matriz no campo finito GF
def invMixColumns(state):
    newState = [[0] * 4 for _ in range(4)]

    for c in range(4):
        newState[0][c] = gmul(0x0e, state[0][c]) ^ gmul(0x0b, state[1][c]) ^ gmul(0x0d, state[2][c]) ^ gmul(0x09, state[3][c])
        newState[1][c] = gmul(0x09, state[0][c]) ^ gmul(0x0e, state[1][c]) ^ gmul(0x0b, state[2][c]) ^ gmul(0x0d, state[3][c])
        newState[2][c] = gmul(0x0d, state[0][c]) ^ gmul(0x09, state[1][c]) ^ gmul(0x0e, state[2][c]) ^ gmul(0x0b, state[3][c])
        newState[3][c] = gmul(0x0b, state[0][c]) ^ gmul(0x0d, state[1][c]) ^ gmul(0x09, state[2][c]) ^ gmul(0x0e, state[3][c])

    for i in range(4):
        for j in range(4):
            state[i][j] = newState[i][j]

    return newState


def decryptAES(ciphertext, key, nonce, rounds=10):
    expanded_key = keyExpansion(key)

    counter = nonce
    cipherBlocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    plaintextBlocks = []

    for block in cipherBlocks:
        if len(block) < 16:
            block = block + bytes(16 - len(block))

        state = [counter[i:i+4] for i in range(0, len(counter), 4)]
        state = addRoundKey(state, expanded_key[rounds * 16:])

        for round in range(rounds - 1, 0, -1):
            state = invShiftRows(state)
            state = invSubBytes(state)
            state = addRoundKey(state, expanded_key[round * 16:(round + 1) * 16])
            state = invMixColumns(state)

        state = invShiftRows(state)
        state = invSubBytes(state)
        state = addRoundKey(state, expanded_key[:16])

        # Concatena as colunas em uma lista
        encrypted_counter = reduce(lambda x, y: x + y, state)

        plaintextBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        plaintextBlocks.append(plaintextBlock)

        counter = CTR(counter)

    plaintext = b''.join(plaintextBlocks)
    plaintext = unpad(plaintext, AES.block_size)
    plaintext = plaintext.decode('utf-8')
    return plaintext
