# Sistema de Autenticação e Métricas

Sistema completo de autenticação JWT com dashboard de métricas desenvolvido em FastAPI (backend) e JavaScript vanilla (frontend).

## 🚀 Funcionalidades

### Autenticação
- ✅ Login seguro com JWT
- ✅ Hash de senhas com bcrypt
- ✅ Middleware de autenticação
- ✅ Controle de acesso baseado em roles (admin/analyst)
- ✅ Validação de tokens

### Dashboard de Métricas
- ✅ Visualização de dados de campanhas
- ✅ Paginação server-side para performance
- ✅ Filtros por data (início/fim)
- ✅ Ordenação por colunas
- ✅ Controle de acesso baseado em role
- ✅ Interface responsiva

## 🛠️ Tecnologias

### Backend
- **FastAPI** - Framework web moderno e rápido
- **bcrypt** - Hash seguro de senhas
- **python-jose** - Geração e validação de tokens JWT
- **pandas** - Manipulação de dados CSV
- **uvicorn** - Servidor ASGI

### Frontend
- **HTML5** - Estrutura semântica
- **CSS3** - Estilização moderna
- **JavaScript ES6+** - Lógica da aplicação
- **Fetch API** - Comunicação com backend

### Dados
- **CSV** - Armazenamento de usuários e métricas
- **JWT** - Autenticação stateless

## Como rodar o backend
1. Certifique-se de que o ambiente virtual está ativado.
2. Execute o backend:
   ```bash
   uvicorn backend.main:app --reload
   ```
   > Altere `main` para o nome do arquivo principal da sua API FastAPI, se necessário.

3. Acesse a documentação interativa em:  
   [http://localhost:8000/docs](http://localhost:8000/docs)

## Dados de Entrada

- Os arquivos `.csv` devem estar na pasta `data/` na raiz do projeto.
- Exemplo de execução de script de teste:
   ```bash
   python backend/test_data.py
   ```

## Autenticação e Perfis de Acesso

A API utiliza autenticação baseada em JWT. O login é feito via endpoint `/login`, validando usuário e senha (armazenados em `users.csv` com hash bcrypt).

- **Admin:** Visualiza todos os campos das métricas, incluindo `cost_micros`.
- **User:** Visualiza as métricas, mas o campo `cost_micros` é ocultado.

### Exemplo de fluxo de autenticação

1. **Login para obter o token JWT:**
   ```bash
   curl -X POST "http://localhost:8000/login" -d "username=user1&password=SENHA_DO_USER1"
   ```
   O retorno será:
   ```json
   {
     "access_token": "SEU_TOKEN_JWT",
     "token_type": "bearer"
   }
   ```

2. **Acessando métricas com o token:**
   ```bash
   curl -H "Authorization: Bearer SEU_TOKEN_JWT" "http://localhost:8000/metrics?start_date=2024-08-01&end_date=2024-08-31&order_by=impressions"
   ```

3. **Exemplo de resposta:**
   ```json
   [
     {
       "account_id": 8181642239,
       "campaign_id": 6320590762,
       "cost_micros": 2026808398.5,
       "clicks": 1306.16,
       "conversions": 60.91,
       "impressions": 43749.27,
       "interactions": 1569.33,
       "date": "2024-08-16"
     }
   ]
   ```

   > Se o usuário não for admin, o campo `cost_micros` não aparecerá.

## Decisões Técnicas

- **FastAPI:** Framework moderno, rápido e com documentação automática, ideal para APIs REST.
- **bcrypt:** Segurança no armazenamento e validação de senhas.
- **JWT:** Permite autenticação stateless, facilitando escalabilidade e integração com frontends modernos.
- **Pandas:** Manipulação eficiente de dados tabulares (CSV), facilitando filtros e ordenações.
- **Arquitetura simples:** Facilita manutenção e entendimento, ideal para processos seletivos e MVPs.

## Observações

- Certifique-se de executar os scripts sempre a partir da raiz do projeto para evitar problemas com caminhos relativos.
- Para dúvidas ou sugestões, consulte a pasta `docs/` ou abra uma issue.

## Licença

Este projeto é apenas para fins de avaliação técnica.
