from cryptography.hazmat.primitives.serialization import load_pem_private_key

# 1. Carregar a chave privada do .pem
with open("chave.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=b"sua_senha_aqui")

# 2. Extrair os números privados (d e n)
priv_numbers = private_key.private_numbers()
d = priv_numbers.d
n = priv_numbers.public_numbers.n

# 3. Mensagem em hex → inteiro
m = 0x169e9b087

# 4. Assinatura RSA textbook (sem padding)
sig = pow(m, d, n)

print(f"Assinatura (int): {sig}")
print(f"Assinatura (hex): {hex(sig)}")