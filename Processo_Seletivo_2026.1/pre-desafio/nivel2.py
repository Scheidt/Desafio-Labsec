from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

# 1. Ler a senha que protege o arquivo .p12
with open("artefatos/nvl2/password.txt", "r") as f:
    password = f.read().strip().encode()

# 2. Ler o arquivo .p12 (contém chave privada + certificado)
with open("artefatos/nvl2/employee.p12", "rb") as f:
    p12_data = f.read()

# 3. Desbloquear o .p12 usando a senha
#    Internamente: senha → PBKDF2 → chave simétrica → descriptografa as "bags"
private_key, cert, chain = pkcs12.load_key_and_certificates(p12_data, password)

print(f"Chave privada: RSA {private_key.key_size} bits")
print(f"Certificado:   {cert.subject}")

# 4. Ler o arquivo cifrado
with open("artefatos/nvl2/access_code.enc", "rb") as f:
    enc_data = f.read()

print(f"Dados cifrados: {len(enc_data)} bytes")

# 5. Descriptografar com RSA-OAEP (SHA-256 como hash, MGF1-SHA-1 como máscara)
resultado = private_key.decrypt(
    enc_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"\nResultado: {resultado.decode('utf-8')}")