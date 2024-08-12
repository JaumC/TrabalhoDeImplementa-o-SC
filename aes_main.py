#AES-128
import random
from aes_encryption import encryptAES
from aes_decryption import decryptAES

#Saída exemplo: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
def keyGen():
    # keyConfirm = input('Você já tem uma chave pronta?[y/n]: ')
    # if keyConfirm == 'y':
    #     key = list(map(lambda x: int(x, 16), input('Informe a chave de 16 bytes (separados por espaços): ').split()))
    # else:
    #     key = [random.randint(0, 255) for _ in range(16)]

    key = [0x70, 0x9a, 0x9c, 0xe4, 0x9e, 0xf5, 0x3d, 0x83, 0xd3, 0x47, 0x42, 0x3d, 0x99, 0xbe, 0x55, 0x30]

    input(f'\nSua chave é[ENTER]:\n{[hex(byte) for byte in key]}')
    return key


def plainText():
    return [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0x4f, 0x9a, 0x20, 0x8c]


def main():
    plaintext = plainText()
    key = keyGen()

    while True:
        loop = input('\nSelecione uma opção:\n1)Encriptar\n2)Decriptar\n3)Sair\nR: ')
        print('')

        if loop == '1':
            ciphertext, rounds = encryptAES(plaintext, key)
            print(ciphertext)
            ciphertexted = [f"{byte:02x}" for byte in ciphertext]
            ciphertexted = ' '.join(ciphertexted)
            print('\nCiphertext', ciphertexted)
            
        elif loop == '2':
            decrypt = decryptAES(ciphertext, key, rounds)
            print(decrypt)
            decrypted = [f"{byte:02x}" for byte in decrypt]
            decrypted = ' '.join(decrypted)
            print('\nDecrypt', decrypted)

        elif loop == '3':
            break

        else:
            print('Opção inválida, tente novamente.\n')

    plaintexted = [f"{byte:02x}" for byte in plaintext]
    plaintexted = ' '.join(plaintexted)

    keyed = [f"{byte:02x}" for byte in key]
    keyed = ' '.join(keyed)

    print('\nPlaintext:', plaintexted)
    print('Key:', keyed)
    print('Ciphertext:', ciphertexted)
    print('Decrypt:', decrypted)
    


main()