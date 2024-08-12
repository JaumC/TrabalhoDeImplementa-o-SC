from aes_constants import S_BOX, MIXCOLUNS
from aes_utils import addRoundKey, gfMult, keyExpasion




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

    for i in range(4):
        for j in range(4):
            newState[j][i] = 0
            for k in range(4):
                newState[j][i] ^= gfMult(MIXCOLUNS[j][k], state[k][i])
    
    return newState


def encryptAES(plaintext, key):
    rounds = int(input('\nDigite a quantidade de rounds: '))
    expanded_key = keyExpasion(key)
    print('expanded', expanded_key)

    state = [list(plaintext[i:i+4]) for i in range(0, 16, 4)]
    state = addRoundKey(state, expanded_key[:16])

    for round in range(1, rounds):
        state = subBytes(state)
        state = shiftRows(state)
        state = mixColumns(state)
        state = addRoundKey(state, expanded_key[round*16:(round+1)*16])
        print('mix ', round, state)

    state = subBytes(state)
    state = shiftRows(state)
    state = addRoundKey(state, expanded_key[round*16:])

    ciphertext = [byte for row in state for byte in row]
    return ciphertext, rounds