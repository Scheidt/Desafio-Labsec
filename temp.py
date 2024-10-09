from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Carrega a chave privada do arquivo PEM
with open("certificado.PEM", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

# Mensagem criptografada em base64
mensagem_base64 = "edWAt9FvUdR/9ekSHEbWZXWeHMBViq0fdri8Y7TAqOjBqIOdhEMe96ZdqitBFAJKzt1xfGhAl/rCJ0mlmbbUt1Tq8c/udmQH+Y8sXtyT5FIg0Hv6wT+nVKGv7Anoi2C+YzrjqCZ6fQuqId6heC3zmgXpwh4nq1oP6vUDWROHIWOO96jesAiffxrvNUq7OHDMeRpszzADu7nXS0QgNviuKB/BciFQfcxI810VCjFa3ctYUYfW1mv7V5gD5/7y10rmJp4m2KM+Mv8vKLXTUgDYCrifgWfP5XW+L4wfjFWGCT1f2spwinoS1czeBXBNdfKI8RxYqKlqrN9rG2FEagZoyXUO3lzxmZNxSyLxODBsC6Fvy9UQr3n8T6XC+J480RMyBefzU+cYvrSASaoMOhc8/FeKvoKeVFP/EX5CMMuvypE1i8YkmeXQE9WyCG3YQl0ZZLg4cLoQx6Y4dfiTAtG7W7FjYr+9etfdjIaxMVIjA3+YgPgoUfXzVxmnMYYqtswhHkNzWStwHjCU7oUxHonFzyYoSnNaqjPs7Vgin2j4KYD+SHLAs6beUxQ4NtYlWgVv+XhD+1nHN+bDxY1WGRl8wt7/zq1lAENDE8TznAjoJMtcP2NNgY3HgWWAW6L7WWqvBpnRYZXXUfGD0GWhZ/5yLgchiOY1ee26hHSM+5iM83I="

# Decodifica a mensagem de base64
mensagem_criptografada = base64.b64decode(mensagem_base64)

try:
    # Descriptografa a mensagem usando OAEP com SHA-256
    mensagem_descriptografada = private_key.decrypt(
        mensagem_criptografada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Mensagem descriptografada:")
    print(mensagem_descriptografada.decode('utf-8'))
except Exception as e:
    print("Falha ao descriptografar a mensagem:")
    print(e)
