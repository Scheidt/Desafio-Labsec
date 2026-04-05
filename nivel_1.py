import hashlib

with open("instructions.pdf", "rb") as f:
    pdf_bytes = f.read()

matricula = "22100919"  # sua string numérica

# 3. Gerar os hashes SHAKE256 (escolha o tamanho de saída em bytes)
tamanho = 32  # 256 bits = 32 bytes

hash_pdf = hashlib.shake_256(pdf_bytes).digest(tamanho)
hash_matricula = hashlib.shake_256(matricula.encode("utf-8")).digest(tamanho)

# 4. XOR bit a bit entre os dois hashes
resultado = bytes(a ^ b for a, b in zip(hash_pdf, hash_matricula))

# 5. Exibir em hexadecimal
print("SHAKE256(PDF):       ", hash_pdf.hex())
print("SHAKE256(Matrícula): ", hash_matricula.hex())
print("XOR (mascaramento):  ", resultado.hex())