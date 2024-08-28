from functools import reduce
from aes_decryption import invMixColumns, invShiftRows, invSubBytes
from aes_encryption import mixColumns, shiftRows, subBytes
from aes_utils import CTR, addRoundKey, hex_string_to_bytes, keyExpansion

def encryptAES(plaintext, key, nonce):
    rounds = int(input('Digite a quantidade de rounds[10, 12 ou 14]: '))

    expanded_key = keyExpansion(key)
    
    # Converter expanded_key em uma lista de listas (4x4) para cada rodada
    expanded_key_4x4 = [list(expanded_key[i:i+16]) for i in range(0, len(expanded_key), 16)]

    counter = nonce

    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    cipherBlocks = []

    for block in blocks:
        state = [list(block[i:i+4]) for i in range(0, len(block), 4)]

        state = addRoundKey(state, expanded_key_4x4[0])

        for round in range(1, rounds):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, expanded_key_4x4[round])

        state = subBytes(state)
        state = shiftRows(state)
        state = addRoundKey(state, expanded_key_4x4[rounds])

        encrypted_counter = bytes(reduce(lambda x, y: x + y, state))

        cipherBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        cipherBlocks.append(cipherBlock)

        counter = CTR(counter)

    ciphertext = b''.join(cipherBlocks)

    return ciphertext, rounds

def decryptAES(ciphertext, key, nonce, rounds=10):
    expanded_key = keyExpansion(key)

    # Converter expanded_key em uma lista de listas (4x4) para cada rodada
    expanded_key_4x4 = [list(expanded_key[i:i+16]) for i in range(0, len(expanded_key), 16)]

    counter = nonce

    cipherBlocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    plaintextBlocks = []

    for block in cipherBlocks:
        state = [list(block[i:i+4]) for i in range(0, len(block), 4)]

        state = addRoundKey(state, expanded_key_4x4[rounds])

        state = invShiftRows(state)
        state = invSubBytes(state)

        for round in range(rounds - 1, 0, -1):
            state = addRoundKey(state, expanded_key_4x4[round])
            state = invMixColumns(state)
            state = invShiftRows(state)
            state = invSubBytes(state)

        state = addRoundKey(state, expanded_key_4x4[0])

        encrypted_counter = bytes(reduce(lambda x, y: x + y, state))

        plaintextBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])

        plaintextBlocks.append(plaintextBlock)

        counter = CTR(counter)

    plaintext = b''.join(plaintextBlocks)

    return plaintext

# Teste do código
plaintext = "Hello, AES encryption and decryption!"
key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
       0xab, 0xf7, 0x97, 0x34, 0x66, 0x08, 0x51, 0xe0]
nonce = b'\x00' * 16  

ciphertext, rounds = encryptAES(plaintext.encode('utf-8'), key, nonce)
print('\n\nCiphertext:', ciphertext, '\nRounds:', rounds)

decrypted = decryptAES(ciphertext, key, nonce, rounds)
print('\nDecrypted Text:', decrypted.decode('utf-8'))
