# Case Engenharia - Sistema de Métricas

## Descrição
Aplicação web para gestores de uma agência de Marketing Digital, exibindo dados de performance a partir de arquivos CSV.

## Estrutura
- `backend/` → API em Python (FastAPI).
- `frontend/` → páginas HTML/JS.
- `data/` → arquivos CSV de entrada.
- `docs/` → documentação adicional.

## Requisitos
- Python 3.9+
- Node.js (se optar por React no frontend)

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

## Observações

- Certifique-se de executar os scripts sempre a partir da raiz do projeto para evitar problemas com caminhos relativos.
- Para dúvidas ou sugestões, consulte a pasta `docs/` ou abra uma issue.

## Licença

Este projeto é apenas para fins de avaliação técnica.
