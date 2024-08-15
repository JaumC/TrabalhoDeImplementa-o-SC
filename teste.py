from aes_decryption import invMixColumns
from aes_encryption import mixColumns


def test_mix_invMixColumns():
    # Matriz de estado original
    original_state = [
        [0x87, 0xf2, 0x4d, 0x97],
        [0x6e, 0x4c, 0x90, 0xec],
        [0x46, 0xe7, 0x4a, 0xc3],
        [0xa6, 0x8c, 0xd8, 0x95]
    ]

    # Clonando o estado original para não alterar o original durante as operações
    state = [row[:] for row in original_state]

    # Aplicando mixColumns
    mixColumns(state)

    # Matriz esperada após mixColumns
    expected_after_mix = [
        [0x47, 0x40, 0xa3, 0x4c],
        [0x37, 0xd4, 0x70, 0x9f],
        [0x94, 0xe4, 0x3a, 0x42],
        [0xed, 0xa5, 0xa6, 0xbc]
    ]

    # Verificando se a matriz após mixColumns corresponde à esperada
    assert state == expected_after_mix, f"Erro no mixColumns. Resultado obtido: {state}"

    # Aplicando invMixColumns para tentar reverter ao estado original
    invMixColumns(state)

    # Verificando se a matriz após invMixColumns volta ao estado original
    assert state == original_state, f"Erro no invMixColumns. Resultado obtido: {state}"

    print("Teste passado com sucesso: mixColumns e invMixColumns estão funcionando corretamente.")

# Chamando o teste
test_mix_invMixColumns()
