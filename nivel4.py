from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# 1. Carregar a chave do .p12
with open("artefatos/nvl3/supervisor.p12", "rb") as f:
    private_key, cert, chain = pkcs12.load_key_and_certificates(f.read(), b"665098625")

# 2. Extrair os números RSA raw
priv_numbers = private_key.private_numbers()
d = priv_numbers.d
n = priv_numbers.public_numbers.n

# 3. Mensagem em hex → inteiro
with open("artefatos/nvl4/number.txt", "r") as f:
    hex_message = f.read().strip()
    m = int(hex_message, 16)

# 4. Assinatura textbook RSA (sem padding)
sig = pow(m, d, n)

print(f"Assinatura (int): {sig}")
print(f"Assinatura (hex): {hex(sig)}")