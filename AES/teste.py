from functools import reduce
import random
from aes_decryption import invMixColumns, invShiftRows, invSubBytes
from aes_encryption import mixColumns, shiftRows, subBytes
from aes_utils import CTR, addRoundKey, keyExpansion, to_hex_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encryptAES(plaintext, key, nonce):
    rounds = int(input('Digite a quantidade de rounds[10, 12 ou 14]: '))
    expanded_key = keyExpansion(key)
    counter = nonce

    plaintext_padded = pad(bytes(plaintext, 'utf-8'), block_size=16)
    print('\nPlaintext com padding:\n', to_hex_string(plaintext_padded))

    blocks = [plaintext_padded[i:i+16] for i in range(0, len(plaintext_padded), 16)]
    print('\nBlocos após divisão:\n', [to_hex_string(block) for block in blocks])

    cipherBlocks = []

    for block in blocks:
        state = [list(block[i:i+4]) for i in range(0, len(block), 4)]
        state = addRoundKey(state, expanded_key[16:])

        for round in range(rounds - 1):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixColumns(state)
            state = addRoundKey(state, expanded_key[(round + 1) * 16:(round + 2) * 16])

        state = subBytes(state)
        state = shiftRows(state)
        state = addRoundKey(state, expanded_key[rounds * 16:])

        encrypted_counter = bytes(reduce(lambda x, y: x + y, state))

        cipherBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        cipherBlocks.append(cipherBlock)

        counter = CTR(counter)

    ciphertext = b''.join(cipherBlocks)
    print('\nTexto cifrado:\n', to_hex_string(ciphertext))

    return ciphertext, rounds



def decryptAES(ciphertext, key, nonce, rounds=10):
    expanded_key = keyExpansion(key)
    counter = nonce
    cipherBlocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    plaintextBlocks = []

    for block in cipherBlocks:
        state = [list(block[i:i+4]) for i in range(0, len(block), 4)]

        # Inicialização
        state = addRoundKey(state, expanded_key[rounds * 16:])

        # Rodadas intermediárias
        for round in range(rounds - 1, 0, -1):
            state = invShiftRows(state)
            state = invSubBytes(state)
            state = addRoundKey(state, expanded_key[round * 16:(round + 1) * 16])
            state = invMixColumns(state)

        # Última rodada
        state = invShiftRows(state)
        state = invSubBytes(state)
        state = addRoundKey(state, expanded_key[:16])

        # Cálculo do contador cifrado
        encrypted_counter = bytes(reduce(lambda x, y: x + y, state))

        # Descriptografia do bloco
        plaintextBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        plaintextBlocks.append(plaintextBlock)

        # Atualização do contador
        counter = CTR(counter)

    plaintext = b''.join(plaintextBlocks)
    plaintext = unpad(plaintext, block_size=16)
    plaintext = plaintext.decode('utf-8')

    return plaintext






def test_aes_encryption_decryption():
    key = b'This is a key123'  # Chave de 16 bytes (128 bits)
    nonce = b'Nonce1234567890'  # Vetor de inicialização (IV) de 16 bytes (128 bits)
    plaintext = 'Hello, AES encryption and decryption!'

    print(f"Texto original:{plaintext}\n")

    # Criptografar o texto
    ciphertext, rounds = encryptAES(plaintext, key, nonce)
    print(f'\nQuantidade de rounds utilizados: {rounds}')
    
    # Descriptografar o texto
    decrypted_text = decryptAES(ciphertext, key, nonce, rounds)
    print("\nTexto descriptografado:", decrypted_text)

    # Verificar se o texto descriptografado corresponde ao texto original
    assert decrypted_text == plaintext, "O texto descriptografado não corresponde ao texto original."

# Execute o teste
test_aes_encryption_decryption()
