from aes_utils import keyExpansion, addRoundKey, bytes_to_state, state_to_bytes, mixColumns, shiftRows, subBytes
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES



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

        # Concatena as colunas em uma lista
        encrypted_counter = state_to_bytes(state)

        plaintextBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        plaintextBlocks.append(plaintextBlock)

        counter += 1

    plaintext = b''.join(plaintextBlocks)
    plaintext = unpad(plaintext, AES.block_size)
    plaintext = plaintext.decode('utf-8')
  
    return plaintext
