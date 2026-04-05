import hashlib

def calcular_hash_shake256(val1, caminho_arquivo, tamanho):
    with open(caminho_arquivo, "rb") as f:
        pdf_bytes = f.read()

    hash_pdf = hashlib.shake_256(pdf_bytes).digest(tamanho)
    hash_val1 = hashlib.shake_256(val1.encode("utf-8")).digest(tamanho)

    # XOR bitwise dos hashes
    resultado = bytes(a ^ b for a, b in zip(hash_pdf, hash_val1))

    # print("SHAKE256(val1): ", hash_matricula.hex())
    # print("SHAKE256(PDF):       ", hash_pdf.hex())
    # print("XOR (mascaramento):  ", resultado.hex())
    return resultado.hex()

if __name__ == "__main__":
    matricula = "22100919"
    caminho_arquivo = "artefatos/nvl1/instructions.pdf"
    tamanho = 64
    resultado = calcular_hash_shake256(matricula, caminho_arquivo, tamanho)
    print("Resultado do XOR (SHAKE256): ", resultado)
