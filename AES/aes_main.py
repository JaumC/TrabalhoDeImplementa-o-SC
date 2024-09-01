# AES-128

from aes_utils import bytes_to_image, image_to_bytes
from aes_encryption import encryptAES
from aes_decryption import decryptAES
from Crypto.Random import get_random_bytes

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
        key_str = input('\nInforme a chave em hexadecimal:\nR: ')
        try:
            key_bytes = bytes.fromhex(key_str)
        except ValueError:
            print("Chave inválida. Deve estar no formato hexadecimal.")
            return

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
        IV_str = input('\nInforme-o em hexadecimal:\nR: ')
        try:
            nonce = bytes.fromhex(IV_str)
        except ValueError:
            print("Nonce inválido. Deve estar no formato hexadecimal.")
            return

        if len(nonce) != 12:
            print("Nonce deve ter exatamente 12 bytes.")
            return
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
            ciphertext = encryptAES(plaintext, key, nonce, rounds)

            print('\nCiphertext:', ciphertext.hex())
            loop = input('\nSelecione uma opção:\n2)Decriptar\n3)Sair\nR: ')
            
        elif loop == '2':
            decrypt = decryptAES(ciphertext, key, nonce, rounds)
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
            with open('../TXTCRYPT/msg_file.txt','rb') as file:
                plaintext = file.read()
            
            ciphertext = encryptAES(plaintext, key, nonce, rounds)

            with open('../TXTCRYPT/ciphed_file.txt', 'wb') as file:
                file.write(ciphertext)

            print(f'Arquivo cifrado salvo em TXTCRYPT/')
            action = input('\nSelecione uma opção:\n2)Decifrar Arquivo\n3)Sair\nR: ')

        elif action == '2':
            with open('../TXTCRYPT/ciphed_file.txt','rb') as file:
                ciphertext = file.read()

            decrypted = decryptAES(ciphertext, key, nonce, rounds)

            with open('../TXTCRYPT/deciphered_file.txt', 'wb') as file:
                file.write(decrypted)

            print(f'Arquivo decifrado salvo em TXTCRYPT/')
            break

        elif action == '3':
            break
        
        else:
            print('Opção inválida, tente novamente.')

def cipherImage():
    print('\nPara a criptografias de imagem, será usado 14 rounds.')

    key = keyGen(14)
    nonce = IVGen()

    steps = input('\nSelecione uma opção:\n1)Cifrar Imagem.\n3)Sair.\nR: ')

    while True:
        if steps == '1':
            img_bytes = image_to_bytes('../IMAGECRYPT/Selfie.jpg')
            
            encrypted_bytes = encryptAES(img_bytes, key, nonce, 14)

            with open(f'../IMAGECRYPT/encryptedIMG.bin', 'wb') as file:
                file.write(encrypted_bytes)

            print(f'Imagem cifrada salva em IMAGECRYPT/')
            steps = input('\nSelecione uma opção:\n2)Decifrar Imagem\n3)Sair\nR: ')

        elif steps == '2':
            
            with open(f'../IMAGECRYPT/encryptedIMG.bin', 'rb') as file:
                encrypted_bytes = file.read()

                decrypted_bytes = decryptAES(encrypted_bytes, key, nonce, 14)

                bytes_to_image(decrypted_bytes, f'../IMAGECRYPT/decryptedIMG.png')

                print(f'Imagem decifrada salva em IMAGECRYPT/')
                break
    

        elif steps == '3':
            break
        
        else:
            print('Opção inválida, tente novamente.')


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