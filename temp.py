from Crypto.PublicKey import RSA

# Sua chave em formato PEM
key_data = '''-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyR0/Gd63EVCb00px5gmj
XqiZgCqS7N6Nasvbc9elesbnzs0xK9FC7f9qsB0iT6xELb+vuUA1l02tl6I4oVwO
G3YZsg4MArt5kzFUN1horFs8N/NPSgHT21mirLtR7H+fJfSaIRN/FzLL/5GfmWFn
ai29RoDHxTc07Ur5eWjtdBPfLQR0AMOQmWpD0uNheD8AI/aarGai+pKXhBMlS5nu
KiPZRdBJi4P72QDFJ0f6lmpXX4MP6gIPsZWLUBR/nM+FMTla/+pbM4onmdqCwB17
BAJ14+BySyeqnwAmoCsUzcHFb+ZhvXtHt4udg5y6dj/000JesFbvJYRfOqUk8Z8A
zxiWNGXhZd/1/xE78+yC1ueaA3efc0iY3KyC6ZmXIu25qFQIDMA1eqPp3/pMRTKw
mqXxl/LbrIczBtYUm4z7WKWYErtEZKq6wlR4Ygh0ncsbm5PgUMqTGtHkGWW0PbAw
LvLTfNv70wJV6pc/iuW1d0YBPhjvQV/8S7V/t9cP13NbQsRLmqoCf9g1G5H60cn/
0ATgpmeKvM3ETApr/laKPeEVXtPpaJ2yaKnscOHxNceniWb+14zgRQFhlCfY/5x2
XLr3NKyrzif9/XW6CIoEr90rC+s4aHVebtTNcfQ/U4BYOwq1DuizDZFEMpPwTILP
1UBq/040wnFE0de3XrGabFUCAwEAAQ==
-----END PUBLIC KEY-----'''

# Importa a chave
try:
    key = RSA.import_key(key_data)
    print(f"Tamanho da chave: {key.size_in_bits()} bits")
    print(f"É uma chave privada? {key.has_private()}")
except ValueError as e:
    print(f"Erro ao importar a chave: {e}")
