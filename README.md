# Case Técnico – Agência de Marketing Digital

## Visão Geral
Aplicação web para gestores visualizarem dados de performance de contas da agência. O projeto demonstra integração entre frontend e backend, autenticação, controle de permissões e manipulação de dados reais.

## Funcionalidades
- Login por email e senha (hash de senha)
- Visualização de dados em tabela
- Filtro por data e ordenação por coluna
- Coluna “cost_micros” visível apenas para admins
- Estrutura organizada e código comentado
- Testes básicos automatizados

## Como Executar
1. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```
2. Inicie o backend:
   ```
   python backend/main.py
   ```
3. Abra `frontend/index.html` no navegador.

Usuários e senhas estão em `data/users.csv`.

## Estrutura do Projeto
- `backend/`: API Python (autenticação, regras de negócio, leitura dos CSVs)
- `frontend/`: HTML/JS puro
- `data/`: arquivos CSV de usuários e métricas
- `tests/`: testes automatizados

## Diferenciais
- Código limpo e comentado
- Facilidade para evoluir (ex: trocar CSV por banco de dados)
- Testes básicos inclusos
- Documentação clara

## Melhorias Futuras
- Cadastro de usuários
- Paginação de dados
- Deploy automatizado

---

**O projeto busca demonstrar domínio dos fundamentos de backend, frontend e integração, com atenção à segurança, organização e clareza.**
