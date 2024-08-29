from aes_utils import keyExpansion, addRoundKey, bytes_to_state, state_to_bytes, mixColumns, shiftRows, subBytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encryptAES(text, key, nonce, rounds):
    plaintext = text.encode('utf-8')
    plaintext = pad(plaintext, AES.block_size)

    counter = 0
    cipherBlocks = []
    expanded_key = keyExpansion(key)
    
    expanded_key_4x4 = [list(expanded_key[i:i+16]) for i in range(0, len(expanded_key), 16)]
    
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)] 

    for block in blocks:
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

        cipherBlock = bytes([b ^ c for b, c in zip(block, encrypted_counter)])
        cipherBlocks.append(cipherBlock)

        counter += 1

    ciphertext = b''.join(cipherBlocks)

    return ciphertext