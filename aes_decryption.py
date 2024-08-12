from aes_constants import INV_S_BOX, INV_MIXCOLUNS
from aes_utils import addRoundKey
from aes_utils import gfMult, keyExpasion

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
    newInvState = [[0] * 4 for _ in range(4)]

    for i in range(4):
        for j in range(4):
            newInvState[j][i] = 0
            for k in range(4):
                newInvState[j][i] ^= gfMult(INV_MIXCOLUNS[j][k], state[k][i])
    
    return newInvState


def decryptAES(ciphertext, key, rounds):
    expanded_key = keyExpasion(key)
    print('expanded', expanded_key)

    state = [list(ciphertext[i:i+4]) for i in range(0, 16, 4)]
    state = addRoundKey(state, expanded_key[rounds*16:(rounds+1)*16])

    for round in range(rounds-1, 0, -1):
        state = addRoundKey(state, expanded_key[round*16:(round+1)*16])
        state = invMixColumns(state)
        state = invShiftRows(state)
        state = invSubBytes(state)
        print('mix ', round, state)

    state = invShiftRows(state)
    state = invSubBytes(state)
    state = addRoundKey(state, expanded_key[:16])

    return [byte for row in state for byte in row]

