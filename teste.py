import hashlib
import os

def oaep_pad(msg, n):
    k = (n.bit_length() + 7) // 8
    l = hashlib.sha3_256(b'').digest()
    hlen = len(l)

    # Padding
    ps = b'\x00' * (k - len(l) - len(msg) - 2)
    db = ps + b'\x01' + msg
    db_mask = os.urandom(len(db))  # Generate random mask for db
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed = os.urandom(hlen)  # Generate random seed
    masked_seed = bytes(x ^ y for x, y in zip(seed, masked_db[:hlen]))

    return masked_seed + masked_db[hlen:], db_mask  # Return db_mask along with padded message

def oaep_unpad(padded, db_mask, n):
    k = (n.bit_length() + 7) // 8
    l = hashlib.sha3_256(b'').digest()
    hlen = len(l)

    masked_seed = padded[:hlen]
    masked_db = padded[hlen:]
    seed = bytes(x ^ y for x, y in zip(masked_seed, db_mask[:hlen]))
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask[hlen:]))

    # Remove padding
    pos = db.find(b'\x01')
    if pos == -1:
        raise ValueError("Invalid padding")
    return db[pos + 1:]

def test_oaep_padding():
    # Parâmetros de teste
    n = 0x01FFFF  # Exemplo de n (deve ser um número maior em uma aplicação real)

    # Mensagem de teste
    message = b'Teste de mensagem para OAEP padding.'

    # Executar padding
    padded_message, db_mask = oaep_pad(message, n)

    # Executar unpadding
    try:
        unpadded_message = oaep_unpad(padded_message, db_mask, n)
        assert unpadded_message == message, "Test failed: the unpadded message does not match the original message."
        print("Test passed: the unpadded message matches the original message.")
    except ValueError as e:
        print(f"Test failed: {e}")

# Executar o teste
test_oaep_padding()
