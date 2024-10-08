from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def descriptografar(mensagem: str, source_chave: str):
    # Carrega a chave privada
    with open(source_chave, 'rb') as f:
        chave_privada = RSA.import_key(f.read())

    # Inicializa o decifrador
    decifrador = PKCS1_OAEP.new(chave_privada)

    # Texto cifrado (em bytes)
    texto_cifrado = base64.b64decode("Bf9RJCkaVqbobncgfBdOoMj0tk0Jf8vr3wc0BV9SLQ+DidTBp+SBP1XNdmbfUgP5crF4vPAS7R4UlBnj35nsYmBzYc44HreCEi2dLiKi+MY7UN54IP7qBG9IzqBA5ZGb8qQF+hpoFeydPXSYrhYja5SxWJvOUrHQ4XmktKDPHJsRQPbmIi8B7/h7R8kFrAkYNBbn2kcS2vmxAtw7APTHMm5xkVt5HV0rbCUALVYDPHLROX6kJ8bt+6/bi5ehl0QmZyyFLyneWGC/EPeFAqoCg3T+HxA5qPXYlol2RWFTsNf2VfybfvV/g7D6Oxu5Qz40wZNRLGtLs/185Ty1aY0UFySFtbkrwDaR6qpybg49vnmtKWzPo5q7TsbmfYT9VEcdgR91VKeAzEbh0RNGmgTtJGqSz8ISqV7KcZdk7KmvhNVOrkyE37fET6C08w6u8WHasHjPnlzEz7Mr+58mFFAiiVUYOwhIOxk5EtdIzsJGOeDnwEtZN+z8hdD+0MVV0K8T23PgNKMHLLy5swGFrQOnFDTa10WH3Sh16Z5qbQiNpk6dHVGKvCeMf7fnxz8xwm84we/oK73SLirbr8mPzPZL0b1FsoTV31jmE9kQfSd84w501ZwGFAsw/gLmviEhRMtcpOApyc5rnsBAkstPTH17xqjdvYR36w2dYqbRHmrHw6Y=")

    # Descriptografa o texto
    texto_descriptografado = decifrador.decrypt(texto_cifrado)

    print(texto_descriptografado.decode('utf-8'))

descriptografar("",'certificado.pem')