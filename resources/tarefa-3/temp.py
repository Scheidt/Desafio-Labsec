from asn1crypto import cms, tsp

# Carregar o arquivo DER
with open('timestamp_token.der', 'rb') as f:
    der_data = f.read()

# Decodificar o PKCS#7
content_info = cms.ContentInfo.load(der_data)

# Extrair o SignedData
signed_data = content_info['content']

# Verificar se há um timeStampToken
for signer_info in signed_data['signer_infos']:
    if 'signed_attrs' in signer_info:
        for attr in signer_info['signed_attrs']:
            if attr['type'].native == 'time_stamp_token':
                # Decodificar o TimeStampToken
                tst = tsp.TimeStampToken.load(attr['values'][0].parsed.dump())
                gen_time = tst['content']['tst_info']['gen_time'].native
                print(f'genTime: {gen_time}')