import os

from aes_utils import image_to_bytes

image_path = './image_crypt/Selfie.jpg'
if not os.path.exists(image_path):
    print(f"Imagem não encontrada em {image_path}")
else:
    img_bytes = image_to_bytes(image_path)
    print("Imagem carregada com sucesso!")
    print(f"Tamanho da imagem em bytes: {len(img_bytes)}")