chave1 = 'resources/tarefa-1/pem/xades_ad_rt_v1.1.pem'
chave2 = 'resources/tarefa-1/pem/xades_b_t.pem'

with open(chave1, 'r') as arq1, open(chave2, 'r') as arq2:
    texto1 = arq1.read()
    texto2 = arq2.read()

if texto1 == texto2:
    print("Iguais")
else:
    print("Diferentes")
