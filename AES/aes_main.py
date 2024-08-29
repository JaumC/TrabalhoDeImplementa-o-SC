# AES-128

from aes_encryption import encryptAES
from aes_decryption import decryptAES
import random


def keyGen(rounds):
    if rounds == 10:
        key_size = 16
    
    elif rounds == 12:
        key_size = 24
    
    elif rounds == 14:
        key_size = 32
    
    else:
        print('\nTamanho de rounds inválido, deve ser[10, 12, 14]')
        return

    keyConfirm = input('\nVocê já tem uma chave pronta?[y/n]: ')

    if keyConfirm == 'y':
        key_str = input('\nInforme a chave:\nR: ')
        key_bytes = key_str.encode('utf-8')

        if len(key_bytes) > key_size:
            key = key_bytes[:key_size]
        elif len(key_bytes) < key_size:
            key = key_bytes.ljust(key_size, b'\0')
        else:
            key = key_bytes
    else:
        key = bytes(random.randint(0, 255) for _ in range(key_size))

    print(f'\nSua chave é: {key.hex()}')
    return key


def IVGen():
    IVConfirm = input('\nVocê já tem um nonce pronto?[y/n]: ')
    
    if IVConfirm == 'y':
        IV_str = input('\nInforme-o:\nR: ')
        IV_bytes = IV_str.encode('utf-8')

        if len(IV_bytes) > 12:
            nonce = IV_bytes[:12]
        elif len(IV_bytes) < 12:
            nonce = IV_bytes.ljust(12, b'\01')
        else:
            nonce = IV_bytes
    else:
        nonce = bytes(random.randint(0, 255) for _ in range(12))

    print(f'\nSeu nonce é: {nonce.hex()}')
    return nonce


def main():
    text = input('\nDigite o texto a ser cifrado:\nR: ')
    rounds = int(input('\nDigite a quantidade de rounds [10, 12 ou 14]: '))

    key = keyGen(rounds)
    nonce = IVGen()

    print('\nPlaintext:', text)

    loop = input('\nSelecione uma opção:\n1)Encriptar\n3)Sair\nR: ')
    while True:

        if loop == '1':
            ciphertext = encryptAES(text, key, nonce, rounds)

            print('\nCiphertext:', ciphertext.hex())
            loop = input('\nSelecione uma opção:\n2)Decriptar\n3)Sair\nR: ')
            
        elif loop == '2':
            decrypt = decryptAES(ciphertext, key, nonce, rounds)
            print('Decrypt:\n', decrypt)
            break

        elif loop == '3':
            break

        else:
            print('Opção inválida, tente novamente.\n')

    print('\nRounds:', rounds)
    print('PlainTxT:', text)
    print('Encrypt:', ciphertext.hex())
    print('Decrypt:', decrypt)
    print('Nonce:', nonce.hex())
    print('Key:', key.hex())

    if decrypt == text:
        print(f'\nSucesso! A fase de encriptação retornou: [ {ciphertext.hex()} ].\nA decriptação retornou: [ {decrypt} ].\nQue é igual ao seu texto original: [ {text} ]\n')
    else:
        print(f'\nFalhou! [ {decrypt} ] != [ {text} ]\n')
    
main()