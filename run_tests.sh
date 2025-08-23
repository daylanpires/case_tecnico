#!/bin/bash
# Script para executar os testes unitários

echo "🧪 Executando Testes Unitários - Sistema de Autenticação e Métricas"
echo "=================================================================="

# Ativar ambiente virtual se necessário
# source .venv/Scripts/activate  # No Windows

echo "📋 Executando todos os testes..."
python -m pytest tests/ -v

echo ""
echo "📊 Executando testes com coverage..."
python -m pytest tests/ --cov=backend --cov-report=term-missing

echo ""
echo "📈 Gerando relatório HTML de coverage..."
python -m pytest tests/ --cov=backend --cov-report=html

echo ""
echo "✅ Testes concluídos!"
echo "📁 Relatório HTML disponível em: htmlcov/index.html"
