import binascii

from aes_constants import RCON, S_BOX

def bytes_to_hex(bytes_list):
    return binascii.hexlify(bytearray(bytes_list)).decode()

def print_key_expansion_result(key, rounds):
    expanded_key = keyExpansion(key, rounds)
    if expanded_key:
        print(f"\nChave expandida para {rounds} rodadas:")
        block_size = 16 if rounds == 10 else (24 if rounds == 12 else 32)
        for i in range(0, len(expanded_key), block_size):
            print(bytes_to_hex(expanded_key[i:i+block_size]))

def keyExpansion(key, rounds):
    # Definições baseadas no número de rodadas
    if rounds == 10:
        key_size = 16
        key_len = 176
    elif rounds == 12:
        key_size = 24
        key_len = 208
    elif rounds == 14:
        key_size = 32
        key_len = 240
    else:
        print('\nNúmero de rodadas inválido, deve ser [10, 12, 14]')
        return

    # Verifica o comprimento da chave
    if len(key) != key_size:
        print(f'Comprimento da chave inválido. Esperado: {key_size} bytes, recebido: {len(key)} bytes')
        return

    expanded_key = [0] * key_len

    # Separa e adiciona as partes da chave
    for i in range(key_size):
        expanded_key[i] = key[i]

    # Expande a chave
    for j in range(key_size, key_len, 4):
        last_bytes = expanded_key[j-4:j]

        # Rotação e aplicação do S-Box
        if j % key_size == 0:
            last_bytes = last_bytes[1:] + last_bytes[:1]
            last_bytes = [S_BOX[b] for b in last_bytes]
            last_bytes[0] ^= RCON[j // key_size - 1]

        elif key_size > 24 and j % key_size == 16:
            last_bytes = [S_BOX[b] for b in last_bytes]

        for l in range(4):
            expanded_key[j + l] = expanded_key[j - key_size + l] ^ last_bytes[l]

    return expanded_key


def main():
    # Chaves de exemplo para os testes
    key_10_rounds = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x97, 0x73, 0x3d, 0x3a, 0x0d, 0x6f])
    
    key_12_rounds = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    
    key_14_rounds = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f])

    # Executa os testes
    print_key_expansion_result(key_10_rounds, 10)
    print_key_expansion_result(key_12_rounds, 12)
    print_key_expansion_result(key_14_rounds, 14)

if __name__ == "__main__":
    main()
