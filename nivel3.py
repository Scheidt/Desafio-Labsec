from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

# 1. Ler o arquivo .p12 (contém chave privada + certificado)
with open("artefatos/nvl3/supervisor.p12", "rb") as f:
    p12_data = f.read()

# 2. Desbloquear o .p12 usando a senha
#    Internamente: senha → PBKDF2 → chave simétrica → descriptografa as "bags"

# Converter senha int para bytes
senha_int =  665098625
senha_bytes = senha_int.to_bytes((senha_int.bit_length() + 7) // 8, byteorder='big')
private_key, cert, chain = pkcs12.load_key_and_certificates(p12_data, senha_bytes)

print(f"Chave privada: RSA {private_key.key_size} bits")
print(f"Certificado:   {cert.subject}")

# 3. Ler o arquivo cifrado
with open("artefatos/nvl3/secret_message.enc", "rb") as f:
    enc_data = f.read()

print(f"Dados cifrados: {len(enc_data)} bytes")

