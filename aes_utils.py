from aes_constants import S_BOX, RCON

#Multiplicação de dois elementos no campo finito GF
def gfMult(a, b):
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return product


#Derivação da key em subkeys para as rodadas de cifração
def keyExpasion(key):
    expanded_key = [0] * 176

    #Separa adciona as partes da chave de 16 em 16
    for i in range(16):
        expanded_key[i] = key[i]

    #Começa do valor 17° ate o 176, saltando de 4 em 4
    for j in range(16, 176, 4):
        last_bytes = expanded_key[j-4:j]
        
        #Rotação e aplicação do SBOX
        if j % 16 == 0:
            last_bytes = last_bytes[1:] + last_bytes[:1]
            
            last_bytes = [S_BOX[b] for b in last_bytes]

            last_bytes[0] ^= RCON[j//16]

        for l in range(4):
            expanded_key[j + l] = expanded_key[j - 16 + l] ^ last_bytes[l]

    return expanded_key

#Aplicação das chaves de rodada para cada bloco do state
def addRoundKey(state, roundKey):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= roundKey[i * 4 + j]
    return state