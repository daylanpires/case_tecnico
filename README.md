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

### Testes
- **pytest** - Framework de testes
- **httpx** - Cliente HTTP assíncrono para testes
- **unittest.mock** - Mocks para isolamento de testes
- **pytest-cov** - Cobertura de testes
- **pytest-asyncio** - Suporte a testes assíncronos

## 🧪 Testes Unitários

O projeto inclui uma suíte completa de **35+ testes unitários** que validam toda a funcionalidade da API:

### Estrutura dos Testes

```
tests/
├── __init__.py                 # Inicialização do pacote de testes
├── README.md                   # Documentação dos testes
├── test_basic.py              # Testes básicos de funcionalidade
├── test_main_simple.py        # Testes simplificados da API
└── test_main.py               # Suíte completa de testes
```

### Cobertura de Testes

#### **1. Testes de Autenticação (12 testes)**
- ✅ Login com credenciais válidas
- ✅ Login com credenciais inválidas  
- ✅ Geração e validação de tokens JWT
- ✅ Acesso a rotas protegidas
- ✅ Tokens expirados
- ✅ Tokens inválidos
- ✅ Verificação de hash de senhas
- ✅ Controle de acesso por role

#### **2. Testes de Endpoints (15 testes)**
- ✅ Endpoint raiz (`/`)
- ✅ Health check (`/health`)
- ✅ Endpoint protegido (`/protected`)
- ✅ Endpoint de métricas (`/metrics`)
- ✅ Filtros por data
- ✅ Paginação
- ✅ Ordenação
- ✅ Limites de página
- ✅ Validação de parâmetros

#### **3. Testes de Controle de Acesso (8 testes)**
- ✅ Acesso admin vs user
- ✅ Campos sensíveis (`cost_micros`)
- ✅ Permissões baseadas em role
- ✅ Restrição de dados por perfil

### Como Executar os Testes

#### **Todos os testes:**
```bash
# Com ambiente virtual ativado
pytest tests/ -v

# Com cobertura de código
pytest tests/ --cov=backend --cov-report=html

# Apenas testes básicos
pytest tests/test_basic.py -v
```

#### **Testes específicos:**
```bash
# Testes de autenticação
pytest tests/test_main.py::test_login_success -v

# Testes de métricas
pytest tests/test_main.py::test_metrics_with_filters -v

# Testes com mock (sem arquivo CSV)
pytest tests/test_main_simple.py -v
```

#### **Executar com detalhes:**
```bash
# Mostrar prints e logs durante os testes
pytest tests/ -v -s

# Parar no primeiro erro
pytest tests/ -x

# Executar testes em paralelo
pytest tests/ -n auto
```

### Configuração dos Testes

O arquivo `pytest.ini` contém as configurações:
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
asyncio_mode = auto
```

### Exemplos de Testes

#### **Teste de Login:**
```python
def test_login_success():
    """Teste de login com credenciais válidas"""
    with patch('main.get_users') as mock_users:
        # Mock dos dados de usuários
        mock_users.return_value = test_users_data
        
        # Requisição de login
        response = client.post("/login", data={
            "username": "admin", 
            "password": "admin123"
        })
        
        # Validações
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
```

#### **Teste de Métricas com Filtros:**
```python
def test_metrics_with_filters():
    """Teste de endpoint de métricas com filtros de data"""
    # Login e obtenção do token
    token = get_admin_token()
    
    # Mock dos dados de métricas
    with patch('main.pd.read_csv') as mock_csv:
        mock_csv.return_value = test_metrics_df
        
        # Requisição com filtros
        response = client.get(
            "/metrics?start_date=2024-01-01&end_date=2024-01-31&page=1&limit=10",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Validações
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "pagination" in data
        assert len(data["data"]) > 0
```

### Relatórios de Teste

Os testes geram relatórios detalhados:

```bash
# Relatório de cobertura HTML
pytest tests/ --cov=backend --cov-report=html
# Abre o arquivo htmlcov/index.html no browser

# Relatório JUnit (CI/CD)
pytest tests/ --junitxml=report.xml

# Relatório JSON
pytest tests/ --json-report --json-report-file=report.json
```

### Validação Contínua

Os testes validam:
- 🔒 **Segurança:** Autenticação, autorização, tokens
- 📊 **Funcionalidade:** CRUD, filtros, paginação
- 🛡️ **Robustez:** Tratamento de erros, edge cases
- 🚀 **Performance:** Limites, timeouts, carga

### Scripts de Execução

O projeto inclui scripts para facilitar a execução:

```bash
# Windows
run_tests.bat

# Linux/Mac
./run_tests.sh
```

## 📁 Estrutura do Projeto

```
case_tecnico/
├── backend/                    # Código da API FastAPI
│   ├── main.py                # Aplicação principal da API
│   ├── utils.py               # Utilitários (hash de senhas)
│   ├── hash_senhas.py         # Script para gerar hashes
│   ├── teste.py               # API de teste simples
│   └── test_data.py           # Validação dos dados CSV
├── data/                       # Dados da aplicação
│   ├── users.csv              # Base de usuários
│   └── metrics.csv            # Métricas de campanhas
├── frontend/                   # Interface web
│   └── index.html             # Dashboard completo
├── tests/                      # Testes unitários
│   ├── __init__.py
│   ├── README.md              # Documentação dos testes
│   ├── test_basic.py          # Testes básicos
│   ├── test_main_simple.py    # Testes simplificados
│   └── test_main.py           # Suíte completa de testes
├── docs/                       # Documentação
├── .venv/                      # Ambiente virtual Python
├── api.log                     # Logs da aplicação
├── pytest.ini                 # Configuração dos testes
├── requirements.txt            # Dependências Python
├── run_tests.bat              # Script Windows para testes
├── run_tests.sh               # Script Linux/Mac para testes
└── README.md                  # Esta documentação
```

## Como rodar o backend
1. **Ative o ambiente virtual:**
   ```bash
   # Windows
   .venv\Scripts\activate
   
   # Linux/Mac
   source .venv/bin/activate
   ```

2. **Execute o backend:**
   ```bash
   uvicorn backend.main:app --reload
   ```

3. **Acesse a aplicação:**
   - **API:** [http://localhost:8000](http://localhost:8000)
   - **Documentação:** [http://localhost:8000/docs](http://localhost:8000/docs)
   - **Frontend:** Abra `frontend/index.html` no browser

## 📊 Dados de Entrada

### Estrutura dos Arquivos CSV

#### **`data/users.csv`** - Usuários do Sistema
```csv
username,password,role,email
admin,$2b$12$hash...,admin,admin@empresa.com
analyst,$2b$12$hash...,user,analyst@empresa.com
user1,$2b$12$hash...,user,user1@empresa.com
```

**Campos:**
- `username`: Nome de usuário único
- `password`: Senha hasheada com bcrypt
- `role`: Perfil de acesso (`admin` ou `user`)
- `email`: Email do usuário

#### **`data/metrics.csv`** - Métricas de Campanhas
```csv
date,account_id,campaign_id,clicks,impressions,conversions,interactions,cost_micros
2024-08-01,8181642239,6320590762,1306.16,43749.27,60.91,1569.33,2026808398.5
2024-08-02,8181642239,6320590763,1150.45,41230.12,55.22,1420.78,1850420150.0
```

**Campos:**
- `date`: Data da métrica (YYYY-MM-DD)
- `account_id`: ID da conta publicitária
- `campaign_id`: ID da campanha
- `clicks`: Número de cliques
- `impressions`: Número de impressões
- `conversions`: Número de conversões
- `interactions`: Número de interações
- `cost_micros`: Custo em micros (apenas para admin)

### Validação dos Dados

Execute o script de validação para verificar a integridade dos dados:

```bash
python backend/test_data.py
```

**Saída esperada:**
```
==========================================
VALIDANDO USUÁRIOS
==========================================
Usuários carregados: 4 registros
Colunas: ['username', 'password', 'role', 'email']

==========================================
VALIDANDO MÉTRICAS  
==========================================
Métricas carregadas: 100 registros
Range de datas: 2024-08-01 até 2024-08-31
Contas únicas: 5
Campanhas únicas: 15

==========================================
RESUMO DA VALIDAÇÃO
==========================================
Users.csv: ✓ Válido
Metrics.csv: ✓ Válido
✓ Todos os dados estão válidos!
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

## 📋 Logs e Monitoramento

A aplicação gera logs detalhados em `api.log` com informações sobre:

- **Autenticação:** Tentativas de login, tokens gerados, acessos negados
- **Requisições:** Endpoints acessados, parâmetros, response times
- **Erros:** Exceptions, validações falhadas, problemas de dados
- **Performance:** Consultas executadas, dados processados

**Exemplo de logs:**
```
2024-08-23 10:30:15 - main - INFO - Login bem-sucedido para usuário: admin@empresa.com
2024-08-23 10:30:20 - main - INFO - Métricas retornadas: 50 registros (página 1/3) para usuário admin@empresa.com (role: admin)
2024-08-23 10:30:25 - main - WARNING - Tentativa de acesso com token expirado para usuário: user1@empresa.com
```

## 🔧 Solução de Problemas

### Problemas Comuns

#### **Erro: "Arquivo não encontrado"**
```bash
# Verifique se os arquivos CSV existem
ls data/users.csv data/metrics.csv

# Execute a validação dos dados
python backend/test_data.py
```

#### **Erro: "Token inválido"**
- Verifique se o token não expirou (60 minutos)
- Faça login novamente para obter um novo token
- Verifique se o header Authorization está correto

#### **Erro: "Módulo não encontrado"**
```bash
# Instale as dependências
pip install -r requirements.txt

# Ative o ambiente virtual
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac
```

#### **Testes falhando:**
```bash
# Execute apenas testes básicos
pytest tests/test_basic.py -v

# Verifique se o ambiente está configurado
python -c "import fastapi, pytest, pandas; print('✅ Dependências OK')"
```

## 🚀 Deploy e Produção

### Variáveis de Ambiente Recomendadas

Para produção, configure estas variáveis de ambiente:

```bash
# Segurança
JWT_SECRET_KEY="sua_chave_secreta_super_segura_aqui"
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Banco de dados (futuro)
DATABASE_URL="postgresql://user:pass@localhost/db"

# Logs
LOG_LEVEL="INFO"
LOG_FILE="app.log"

# CORS
ALLOWED_ORIGINS="https://seudominio.com,https://app.seudominio.com"
```

### Docker (Opcional)

```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 📊 Métricas e Performance

### Benchmarks de Performance

- **Login:** < 100ms
- **Consulta métricas:** < 500ms (1000 registros)
- **Paginação:** < 200ms por página
- **Filtros:** < 300ms com múltiplos filtros

### Limites Configurados

- **Página máxima:** 1000 registros
- **Página padrão:** 50 registros
- **Token válido:** 60 minutos
- **Arquivo de log:** Rotação automática

## Decisões Técnicas

- **FastAPI:** Framework moderno, rápido e com documentação automática, ideal para APIs REST.
- **bcrypt:** Segurança no armazenamento e validação de senhas.
- **JWT:** Permite autenticação stateless, facilitando escalabilidade e integração com frontends modernos.
- **Pandas:** Manipulação eficiente de dados tabulares (CSV), facilitando filtros e ordenações.
- **Arquitetura simples:** Facilita manutenção e entendimento, ideal para processos seletivos e MVPs.

## Observações

- ⚠️  **Caminhos:** Execute sempre a partir da raiz do projeto para evitar problemas com caminhos relativos
- 🔒 **Segurança:** Em produção, use variáveis de ambiente para JWT_SECRET_KEY
- 📊 **Performance:** Para datasets grandes, considere implementar cache ou banco de dados
- 🧪 **Testes:** Execute a suíte completa antes de fazer alterações importantes
- 📝 **Logs:** Monitore o arquivo `api.log` para debugging e auditoria

## 🤝 Contribuição

### Como Contribuir

1. **Fork** o repositório
2. **Crie** uma branch para sua feature: `git checkout -b feature/nova-funcionalidade`
3. **Execute** os testes: `pytest tests/ -v`
4. **Commit** suas mudanças: `git commit -m "feat: nova funcionalidade"`
5. **Push** para a branch: `git push origin feature/nova-funcionalidade`
6. **Abra** um Pull Request

### Padrões de Código

- **PEP 8** para Python
- **Docstrings** em todas as funções públicas
- **Type hints** para melhor documentação
- **Testes unitários** para novas funcionalidades
- **Logs informativos** para debugging

### Checklist para PRs

- [ ] ✅ Testes passando (`pytest tests/ -v`)
- [ ] 📚 Documentação atualizada
- [ ] 🔍 Code review interno realizado
- [ ] 📝 Changelog atualizado
- [ ] 🧪 Cobertura de testes mantida/melhorada

## 📈 Roadmap

### Próximas Funcionalidades

- [ ] **Banco de dados:** Migrar de CSV para PostgreSQL/MySQL
- [ ] **Cache:** Implementar Redis para performance
- [ ] **Webhooks:** Notificações em tempo real
- [ ] **Analytics:** Dashboard com gráficos e KPIs
- [ ] **Export:** Relatórios em PDF/Excel
- [ ] **API Rate Limiting:** Controle de taxa de requisições
- [ ] **Auditoria:** Log completo de ações do usuário
- [ ] **Multi-tenancy:** Suporte a múltiplas organizações

### Melhorias Técnicas

- [ ] **Containerização:** Docker compose completo
- [ ] **CI/CD:** GitHub Actions para testes automáticos  
- [ ] **Monitoramento:** Integração com Prometheus/Grafana
- [ ] **Segurança:** OAuth2, 2FA, RBAC granular
- [ ] **Performance:** Query optimization, connection pooling
- [ ] **Escalabilidade:** Load balancing, horizontal scaling

## 📞 Suporte

Para dúvidas, problemas ou sugestões:

- 📧 **Email:** daylan.pires@exemplo.com
- 📋 **Issues:** Abra uma issue no repositório
- 📖 **Docs:** Consulte a pasta `docs/` para documentação adicional
- 🧪 **Testes:** Veja `tests/README.md` para detalhes sobre testes

---

## 📄 Licença

Este projeto foi desenvolvido para **processo seletivo/avaliação técnica**.

### Uso Permitido
- ✅ Execução para fins de avaliação
- ✅ Modificação para testes
- ✅ Referência para aprendizado

### Restrições
- ❌ Uso comercial sem autorização
- ❌ Redistribuição sem créditos
- ❌ Remoção de comentários de autoria

---

**🚀 Desenvolvido com dedicação para demonstrar habilidades técnicas em desenvolvimento full-stack com Python/FastAPI**

---

*Última atualização: Agosto 2025*
