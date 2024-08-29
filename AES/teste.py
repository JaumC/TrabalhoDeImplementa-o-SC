from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import binascii
from aes_encryption import mixColumns, shiftRows, subBytes
from aes_utils import addRoundKey, keyExpansion

def bytes_to_state(block):
    """Converte um bloco de bytes em uma matriz 4x4."""
    return [list(block[i:i+4]) for i in range(0, len(block), 4)]

def state_to_bytes(state):
    """Converte uma matriz 4x4 em um bloco de bytes."""
    return bytes([item for sublist in state for item in sublist])

def encryptAES(plaintext, key, nonce, rounds):
    counter = 0
    cipherBlocks = []
    expanded_key = keyExpansion(key)

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
text = "This is a test message for AES encryption."
key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x97\x34\x66\x08\x51\xe0'
nonce = b'\x01' * 12

plaintext = text.encode('utf-8')
plaintext = pad(plaintext, AES.block_size)

ciphertext, rounds = encryptAES(text, key, nonce)
print('\nCiphertext:', binascii.hexlify(ciphertext))

decrypted = decryptAES(ciphertext, key, nonce, rounds)
decrypted = unpad(decrypted, AES.block_size)
print('\nDecrypted Text:', decrypted.decode('utf-8'))

# Verificar se o texto descriptografado corresponde ao plaintext original
if decrypted.decode('utf-8') == text:
    print("\nSuccess! The decrypted text matches the original plaintext.")
else:
    print("\nFailure! The decrypted text does not match the original plaintext.")