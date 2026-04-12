# Desafio do PBAD - Implementar PSC

Nesta etapa você deve implementar uma aplicação PSC (Provedor de Serviços de Confiança) utilizando o framework Spring Boot
seguinda a normativa [DOC-ICP-17.01](https://www.gov.br/iti/pt-br/assuntos/legislacao/instrucoes-normativas/IN_20_2020_DOC_17.01_assinada.pdf).

Mais especificamente você deve implementar utilizando a estrutura de código oferecida os serviços de:

- Cadastro de Aplicação (`/oauth/application`)
- Autorização de Aplicação (`/oauth/authorize`)
- Geração de Token (`/oauth/token`)
- Assinatura (`/oauth/signature`)
- Descoberta de Certificado (`/oauth/certificate-discovery`)
- Descoberta de Usuário (`/oauth/user-discovery`)

## Execução

É necessário criar um arquivo `.env` na raiz do projeto com base na estrutura do arquivo
`.env.example` para configurar as variáveis de ambiente necessárias para a execução da aplicação.

Foi disponibilizado um
`docker-compose.yml` para facilitar a execução da aplicação utilizando Docker. Para iniciar a aplicação, execute o seguinte comando no terminal:

```bash
docker compose up
```

### Observação

- A aplicação utiliza um banco de dados PostgreSQL para armazenar as informações necessárias. Certifique-se de que o banco de dados esteja configurado corretamente no arquivo
  `.env` antes de iniciar a aplicação.
- Caso decida executar a aplicação localmente lembre-se de configurar o endereço do banco de dados
  no arquivo `.env` para _localhost_. Por padrão, o banco de dados é configurado para rodar em uma rede interna docker.
- É possivel limpar o volume do banco de dados utilizando o comando
  `docker compose down -v`, recriando o banco na próxima execução.

## O que já foi implementado

- Estrutura de código base utilizando Spring Boot
- Modelos de dados para as entidades principais (Aplicação, Sessão, Usuário, etc.)
- Repositórios para acesso ao banco de dados
- Controladores com os endpoints definidos na normativa DOC-ICP-17.01

## O que falta implementar

O que falta implementar é identificável no código ou por uma exceção `ImplementMe` ou por um `TODO`.
Resumidamente, as principais tarefas a serem implementadas são:

- Lógica de negócio para cada um dos serviços (cadastro, autorização, geração de token, etc.)
- Validação de dados de entrada
- Gerenciamento de sessões e tokens
- Geração dos usuários no banco de dados (`LoadDatabase.java`).

## Não será cobrado

- **/oauth/authorize**: _signature_session_ e _authentication_session_ no **scope**
    - apenas _single_signature_ e _multi_signature_ devem ser implementados!
- **/oauth/signature**: **signature_format** com valor _CMS_
    - apenas _RAW_ deve ser implementado!

## Notas para `/oauth/authorize`

- A normativa especifica o formato `application/x-www-form-urlencoded` para os dados de entrada,
  no entanto, o SpringBoot não suporta esse formato para requisições do tipo GET, portanto, os dados de entrada devem ser enviados como query parameters.
  O método já está pré-configurado para receber os dados como query parameters, portanto, não é necessário alterar o método para receber os dados no corpo da requisição.
- A rota retorna uma página de autorização. Para fins de teste, a página de autorização já está pré-configurada com um botão de autorizar ou negar.
    - Após autorizado a aplicação deve redirecionar para a URL de redirecionamento com o código de autorização, conforme especificado na normativa.
    - A rota de redirecionamento também foi parcialmente implementada.
      Então, todo usuário deve ser cadastrado com a rota de redirecionamento `http://localhost:{port}/redirect/{cpf}`,
      onde `{port}` é a porta onde a aplicação está rodando e `{cpf}` é o CPF do usuário cadastrado.
    - Os controladores em questão são `AuthorizationController` e `RedirectController`, respectivamente.

## Como será avaliado

A avaliação será com base na aplicação em Docker, onde serão testados os endpoints utilizando ferramentas internas do
PBAD. Adicionalmente, será avaliada a qualidade do código, organização, clareza e aderência a normativa DOC-ICP-17.01.

Você tem total liberdade para modificar a estrutura inicial apresentada e organizar o código da maneira que achar mais adequada, desde que os endpoints e funcionalidades exigidos sejam implementados corretamente.