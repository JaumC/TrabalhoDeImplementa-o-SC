# AES-128

import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from aes_encryption import encryptAES
from aes_decryption import decryptAES
from aes_utils import to_hex_string

#Saída exemplo: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
def keyGen():
    keyConfirm = input('Você já tem uma chave pronta?[y/n]: ')
    if keyConfirm == 'y':
        key = list(map(lambda x: int(x, 16), input('Informe a chave de 16 bytes (separados por espaços): ').split()))
    else:
        key = [random.randint(0, 255) for _ in range(16)]

    input(f'\nSua chave é[ENTER]: {to_hex_string(key)}')
    return key


def plainText():
    text = input('Digite seu texto para criptografia: ')
    text_bytes = text.encode('utf-8')
    padding = pad(text_bytes, AES.block_size)
    plaintext = list(padding)
    return plaintext


def main():
    plaintext = plainText()
    key = keyGen()
    nonce = [0] * 16
    print('\nPlaintext:\n', to_hex_string(plaintext))

    loop = input('\nSelecione uma opção:\n1)Encriptar\n3)Sair\nR: ')
    while True:

        if loop == '1':
            ciphertext, rounds = encryptAES(plaintext, key, nonce)
            print('Ciphertext:\n', to_hex_string(ciphertext))
            loop = input('\nSelecione uma opção:\n2)Decriptar\n3)Sair\nR: ')
            
        elif loop == '2':
            decrypt = decryptAES(ciphertext, key, nonce, rounds)
            print('Decrypt:\n', to_hex_string(decrypt))
            break

        elif loop == '3':
            break

        else:
            print('Opção inválida, tente novamente.\n')

    print('\nPlaintext:\n', to_hex_string(plaintext))
    print('Key:\n', to_hex_string(key))
    print('Ciphertext:\n', to_hex_string(ciphertext))
    print('Decrypt:\n', to_hex_string(decrypt))
    
main()