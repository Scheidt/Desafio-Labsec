chave1 = 'comparar/cades_ad_rb_v2.3.txt'
chave2 = 'comparar/cm2_2.txt'

with open(chave1, 'r') as arq1, open(chave2, 'r') as arq2:
    texto1 = arq1.read()
    texto2 = arq2.read()

if texto1 == texto2:
    print("Iguais")
else:
    print("Diferentes")
