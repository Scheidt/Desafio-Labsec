# Guia de Inicialização e Testes

## Pré-requisitos

- [Docker](https://www.docker.com/) e Docker Compose instalados
- Conexão com a internet (a aplicação baixa o certificado CA da UFSC na primeira inicialização)

---

## 1. Configurar variáveis de ambiente (opcional)

O `docker-compose.yml` já define valores padrão para todas as variáveis via `${VAR:-default}`, então **o arquivo `.env` não é obrigatório** para rodar com Docker.

Crie um `.env` apenas se quiser sobrescrever algum valor padrão:

```bash
cp .env.example .env
# edite conforme necessário
```

> **Execução local (sem Docker):** crie o `.env` com `DB_HOST=localhost` para apontar para o PostgreSQL local.

---

## 2. Subir a aplicação com Docker

```bash
docker compose up --build
```

Isso irá:
1. Compilar a aplicação Java 21 (Maven)
2. Subir um container PostgreSQL 15
3. Subir a aplicação na porta **8080**
4. Criar automaticamente dois usuários de teste no banco de dados na primeira execução

Para parar:

```bash
docker compose down
```

Para limpar o banco de dados (recria tudo do zero):

```bash
docker compose down -v
```

---

## 3. Verificar que a aplicação está no ar

```bash
curl http://localhost:8080/oauth/user-discovery?cpf=13174020905
```

Se retornar um JSON com dados do usuário, a aplicação está funcionando.

---

## 4. Usuários pré-cadastrados

A aplicação cria dois usuários automaticamente na inicialização:

| Nome | CPF | Algoritmo padrão | Redirect URI |
|------|-----|-----------------|--------------|
| Pedro-22100919 | `13174020905` | RSA | `http://localhost:8080/redirect/13174020905` |
| Pedro-22100919-PQC | `13174020906` | MLDSA | `http://localhost:8080/redirect/13174020906` |

---

## 5. Fluxo completo de teste

### 5.1 Cadastrar uma aplicação cliente

```bash
curl -X POST http://localhost:8080/oauth/application \
  -H "Content-Type: application/json" \
  -d '{
    "name": "meu-app",
    "email": "teste@mail.com",
    "redirectUris": ["http://localhost:8080/redirect/13174020905"]
  }'
```

Guarde o `client_id` e `client_secret` retornados.

---

### 5.2 Gerar o PKCE (code_verifier + code_challenge)

O fluxo OAuth usa PKCE (S256). Você deve rodar o arquivo python fornecido ou
realizar o próprio PKCE. Guarde os seguintes dados:
  code verifier
  code challange

É possível rodar o script python por meio dos seguintes comandos:
```powershell
python3 pkceCreator.py
```
Caso o comando acima não funcionar, tente:
```powershell
python pkceCreator.py
```

---

### 5.3 Solicitar autorização (abre no navegador)

Acesse no navegador (substitua os valores):

```
http://localhost:8080/oauth/authorize
  ?response_type=code
  &client_id=<CLIENT_ID>
  &redirect_uri=http://localhost:8080/redirect/13174020905
  &scope=single_signature
  &code_challenge=<CODE_CHALLENGE>
  &code_challenge_method=S256
  &login_hint=13174020905
```


Clique em **Autorizar** na página exibida. Você será redirecionado para:

```
http://localhost:8080/redirect/13174020905?code=<AUTHORIZATION_CODE>&state=...
```

Copie o `code` da URL, o código também estará disponível na interface web.

---

### 5.4 Obter o token de acesso

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "code=<AUTHORIZATION_CODE>" \
  -d "redirect_uri=http://localhost:8080/redirect/13174020905" \
  -d "code_verifier=<CODE_VERIFIER>"
```


Guarde o `access_token` retornado.

---

### 5.5 Assinar um hash

```bash
curl -X POST http://localhost:8080/oauth/signature \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{
    "certificateAlias": "RSA",
    "hashes": [
      {
        "id": "doc1",
        "hash": "<HASH_BASE64>",
        "hashAlgorithm": "SHA-256",
        "signatureFormat": "RAW"
      }
    ]
  }'
```


---

### 5.6 Descoberta de usuário

```bash
curl "http://localhost:8080/oauth/user-discovery?clientId=<CLIENT_ID>&clientSecret=<CLIENT_SECRET>&userCpfCnpj=13174020905"
```

---

### 5.7 Descoberta de certificado

```bash
curl -H "Authorization: Bearer <ACCESS_TOKEN>" \
  "http://localhost:8080/oauth/certificate-discovery?cpf=13174020905"
```


---

## 6. Executar os testes automatizados

```bash
# Com Maven Wrapper (sem Docker)
./mvnw test

# Ou com Maven instalado
mvn test
```

---

## 7. Execução local (sem Docker)

Requisito: PostgreSQL rodando localmente na porta 5432.

1. Ajuste `.env` com `DB_HOST=localhost`
2. Execute:

```bash
./mvnw spring-boot:run
```

A aplicação sobe na porta **8080** por padrão.
