# 🧪 Testes Unitários - Sistema de Autenticação e Métricas

Este diretório contém uma suíte completa de testes unitários para o sistema de autenticação JWT e API de métricas.

## 📋 Cobertura de Testes

### 🔐 Testes de Autenticação (`TestAuthentication`)
- ✅ **Endpoint raiz** - Verifica se API está online
- ✅ **Login admin** - Autenticação de administrador
- ✅ **Login user** - Autenticação de usuário comum  
- ✅ **Credenciais inválidas** - Tratamento de senhas incorretas
- ✅ **Usuário inexistente** - Tratamento de usuários não cadastrados
- ✅ **Endpoint protegido** - Acesso com/sem token JWT
- ✅ **Token expirado** - Validação de expiração de tokens
- ✅ **Token inválido** - Tratamento de tokens malformados

### 📊 Testes de Métricas (`TestMetricsEndpoint`)
- ✅ **Acesso admin** - Visualização completa incluindo `cost_micros`
- ✅ **Acesso user** - Visualização limitada sem dados financeiros
- ✅ **Filtros de data** - Funcionalidade de filtros por período
- ✅ **Paginação** - Sistema de páginas com limit/offset
- ✅ **Ordenação** - Ordenação por diferentes campos
- ✅ **Autorização** - Proteção contra acesso não autorizado
- ✅ **Tratamento de erros** - Arquivo CSV não encontrado

### 🔧 Testes de Utilidades (`TestUtilityFunctions`)
- ✅ **Verificação de senhas** - Hash bcrypt correto/incorreto
- ✅ **Criação de tokens JWT** - Geração de tokens válidos
- ✅ **Autenticação de usuário** - Fluxo completo de auth
- ✅ **Falhas de autenticação** - Tratamento de erros

### 📁 Testes de Integridade (`TestDataIntegrity`)
- ✅ **Estrutura CSV users** - Colunas obrigatórias presentes
- ✅ **Tratamento de erros** - Arquivos não encontrados

### 🌐 Testes da API (`TestAPIEndpoints`)
- ✅ **Existência de endpoints** - Todos os endpoints principais
- ✅ **Headers CORS** - Configuração de CORS
- ✅ **Content-Type** - Retorno em JSON

## 🚀 Como Executar

### Instalar dependências:
```bash
pip install pytest pytest-cov pytest-asyncio httpx
```

### Executar todos os testes:
```bash
pytest tests/ -v
```

### Executar testes específicos:
```bash
# Apenas testes de autenticação
pytest tests/test_main.py::TestAuthentication -v

# Apenas testes de métricas  
pytest tests/test_main.py::TestMetricsEndpoint -v

# Teste específico
pytest tests/test_main.py::TestAuthentication::test_login_success_admin -v
```

### Executar com coverage:
```bash
pytest tests/ --cov=backend --cov-report=html
```
Gera relatório HTML em `htmlcov/index.html`

### Executar com coverage no terminal:
```bash
pytest tests/ --cov=backend --cov-report=term-missing
```

## 📊 Relatório de Coverage

Os testes cobrem:
- **Autenticação JWT** completa
- **Controle de permissões** por roles
- **API endpoints** com todos os cenários
- **Validação de dados** de entrada
- **Tratamento de erros** robusto
- **Funções utilitárias** essenciais

## 🎯 Tecnologias Utilizadas

- **pytest**: Framework de testes principal
- **pytest-cov**: Relatórios de coverage
- **unittest.mock**: Mocks e patches para isolamento
- **FastAPI TestClient**: Cliente de teste HTTP
- **pandas**: Manipulação de dados de teste

## ✅ Qualidade do Código

Os testes seguem boas práticas:
- **Isolamento**: Cada teste é independente
- **Mocking**: Dependências externas são mockadas
- **Clareza**: Nomes descritivos e documentação
- **Cobertura**: Cenários positivos e negativos
- **Organização**: Agrupados por funcionalidade
