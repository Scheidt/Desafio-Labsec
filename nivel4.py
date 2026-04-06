from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# Carregar a chave privada do arquivo PKCS#12
with open("artefatos/nvl3/supervisor.p12", "rb") as f:
    private_key, cert, chain = pkcs12.load_key_and_certificates(f.read(), b"665098625")

# Extrair os parâmetros da chave RSA
priv_numbers = private_key.private_numbers()
d = priv_numbers.d
n = priv_numbers.public_numbers.n

# Ler a mensagem hexadecimal do arquivo
with open("artefatos/nvl4/number.txt", "r") as f:
    hex_message = f.read().strip()
    m = int(hex_message, 16)

# Gerar a assinatura RSA usando a chave privada e a mensagem
sig = pow(m, d, n)

print(f"Assinatura (hex): {hex(sig)}")