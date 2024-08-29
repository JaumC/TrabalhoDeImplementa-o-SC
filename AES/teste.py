from functools import reduce
from aes_encryption import mixColumns, shiftRows, subBytes
from aes_utils import addRoundKey, keyExpansion

def bytes_to_state(block):
    """Converte um bloco de bytes em uma matriz 4x4."""
    return [list(block[i:i+4]) for i in range(0, len(block), 4)]

def state_to_bytes(state):
    """Converte uma matriz 4x4 em um bloco de bytes."""
    return bytes([item for sublist in state for item in sublist])

def encryptAES(plaintext, key, nonce):
    counter = 0
    cipherBlocks = []
    expanded_key = keyExpansion(key)
    
    rounds = int(input('Digite a quantidade de rounds [10, 12 ou 14]: '))

    expanded_key_4x4 = [list(expanded_key[i:i+16]) for i in range(0, len(expanded_key), 16)]

    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    for block in blocks:
        # Combina o nonce com o contador para formar o bloco de entrada do contador
        counter_block = nonce + counter.to_bytes(4, byteorder='big')
        state = bytes_to_state(counter_block)

        state = addRoundKey(state, expanded_key_4x4[0])

        for round in range(1, rounds):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, expanded_key_4x4[round])

        state = subBytes(state)
        state = shiftRows(state)
        state = addRoundKey(state, expanded_key_4x4[rounds])

        # Gera o "bloco cifrado do contador"
        encrypted_counter = state_to_bytes(state)

        # Realiza a operação XOR entre o bloco de texto simples e o bloco cifrado do contador
        cipherBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        cipherBlocks.append(cipherBlock)

        # Incrementa o contador para o próximo bloco
        counter += 1

    ciphertext = b''.join(cipherBlocks)

    return ciphertext, rounds


def decryptAES(ciphertext, key, nonce, rounds=10):
    counter = 0
    plaintextBlocks = []
    expanded_key = keyExpansion(key)

    expanded_key_4x4 = [list(expanded_key[i:i+16]) for i in range(0, len(expanded_key), 16)]

    cipherBlocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    for block in cipherBlocks:
        counter_block = nonce + counter.to_bytes(4, byteorder='big')
        
        state = bytes_to_state(counter_block)
        
        state = addRoundKey(state, expanded_key_4x4[0])

        for round in range(1, rounds):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, expanded_key_4x4[round])

        state = subBytes(state)
        state = shiftRows(state)
        state = addRoundKey(state, expanded_key_4x4[rounds])

        encrypted_counter = state_to_bytes(state)

        plaintextBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        plaintextBlocks.append(plaintextBlock)

        counter += 1

    plaintext = b''.join(plaintextBlocks)

    return plaintext


# Teste do código
plaintext = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x34, 0x66, 0x08, 0x51, 0xe0])
key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x34, 0x66, 0x08, 0x51, 0xe0])
nonce = b'\x00' * 12  # CTR usa nonce de 12 bytes

ciphertext, rounds = encryptAES(plaintext, key, nonce)
print('\n\nCiphertext:', ciphertext, '\nRounds:', rounds)

decrypted = decryptAES(ciphertext, key, nonce, rounds)
print('\nDecrypted Text:', decrypted)

# Verificar se o texto descriptografado corresponde ao plaintext original
if decrypted == plaintext:
    print("Success! The decrypted text matches the original plaintext.")
else:
    print("Failure! The decrypted text does not match the original plaintext.")