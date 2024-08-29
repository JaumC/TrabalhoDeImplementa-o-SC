# AES-128

from aes_encryption import encryptAES
from aes_decryption import decryptAES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


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
        key = get_random_bytes(key_size)

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
        nonce = get_random_bytes(12)


    print(f'\nSeu nonce é: {nonce.hex()}')
    return nonce


def cipherText():
    text = input('\nDigite o texto a ser cifrado:\nR: ')
    rounds = int(input('\nDigite a quantidade de rounds [10, 12 ou 14]: '))

    key = keyGen(rounds)
    nonce = IVGen()

    print('\nPlaintext:', text)

    loop = input('\nSelecione uma opção:\n1)Encriptar\n3)Sair\nR: ')
    while True:

        if loop == '1':
            plaintext = text.encode('utf-8')
            plaintext = pad(plaintext, AES.block_size)
            ciphertext = encryptAES(plaintext, key, nonce, rounds)

            print('\nCiphertext:', ciphertext.hex())
            loop = input('\nSelecione uma opção:\n2)Decriptar\n3)Sair\nR: ')
            
        elif loop == '2':
            decrypt = decryptAES(ciphertext, key, nonce, rounds)
            decrypt = unpad(decrypt, AES.block_size)
            decrypt = decrypt.decode('utf-8')
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
    


def cipherFile():
    rounds = int(input('\nDigite a quantidade de rounds [10, 12 ou 14]: '))

    key = keyGen(rounds)
    nonce = IVGen()

    action = input('\nSelecione uma opção:\n1)Cifrar Arquivo\n2)Decifrar Arquivo\n3)Sair\nR: ')

    while True:
        if action == '1':
            with open('msg_file.txt','rb') as file:
                plaintext = file.read()
            
            plaintext = pad(plaintext, AES.block_size)
            ciphertext = encryptAES(plaintext, key, nonce, rounds)

            with open('ciphed_file.txt', 'wb') as file:
                file.write(ciphertext)

            print(f'Arquivo cifrado salvo!')
            action = input('\nSelecione uma opção:\n1)Cifrar Arquivo\n2)Decifrar Arquivo\n3)Sair\nR: ')

        elif action == '2':
            with open('ciphed_file.txt','rb') as file:
                ciphertext = file.read()

            decrypted = decryptAES(ciphertext, key, nonce, rounds)
            plaintext = unpad(decrypted, AES.block_size)

            with open('deciphered_file.txt', 'wb') as file:
                file.write(plaintext)

            print(f'Arquivo decifrado salvo!')
            break

        elif action == '3':
            break
        
        else:
            print('Opção inválida, tente novamente.')

def cipherImage():
    pass

def main():
    while True:
        response = input('\nEscolha a opção:\n1)Cifração de Texto.\n2)Cifração de Arquivo.\n3)Cifrar Imagem.\n4)Sair\nR: ')
        if response == '1':
            cipherText()
        elif response == '2':
            cipherFile()
        elif response == '3':
            cipherImage()
        elif response == '4':
            break
        else:
            print('Opção inválida, tente novamente.')

main()