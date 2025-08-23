@echo off
REM Script para executar os testes unitários no Windows

echo 🧪 Executando Testes Unitários - Sistema de Autenticação e Métricas
echo ==================================================================

echo 📋 Executando todos os testes...
C:/Users/dayla/Desktop/case_tecnico/.venv/Scripts/python.exe -m pytest tests/ -v

echo.
echo 📊 Executando testes com coverage...
C:/Users/dayla/Desktop/case_tecnico/.venv/Scripts/python.exe -m pytest tests/ --cov=backend --cov-report=term-missing

echo.
echo 📈 Gerando relatório HTML de coverage...
C:/Users/dayla/Desktop/case_tecnico/.venv/Scripts/python.exe -m pytest tests/ --cov=backend --cov-report=html

echo.
echo ✅ Testes concluídos!
echo 📁 Relatório HTML disponível em: htmlcov/index.html
pause
