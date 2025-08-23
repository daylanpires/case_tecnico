#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para testar e validar os dados CSV
Verifica se os arquivos users.csv e metrics.csv estão no formato correto

Uso:
    python test_data.py
"""

import os
import pandas as pd
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_users_data(filepath: str) -> bool:
    """
    Valida o arquivo users.csv
    
    Args:
        filepath (str): Caminho para o arquivo users.csv
        
    Returns:
        bool: True se válido, False caso contrário
    """
    try:
        df = pd.read_csv(filepath)
        logger.info(f"Usuários carregados: {len(df)} registros")
        logger.info(f"Colunas: {list(df.columns)}")
        
        # Verificar colunas obrigatórias
        required_columns = ['username', 'password', 'role']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            logger.error(f"Colunas obrigatórias ausentes: {missing_columns}")
            return False
            
        # Verificar dados
        logger.info("\nPrimeiros registros:")
        for _, row in df.head().iterrows():
            logger.info(f"User: {row['username']}, Role: {row['role']}")
            
        return True
        
    except Exception as e:
        logger.error(f"Erro ao validar users.csv: {e}")
        return False

def validate_metrics_data(filepath: str) -> bool:
    """
    Valida o arquivo metrics.csv
    
    Args:
        filepath (str): Caminho para o arquivo metrics.csv
        
    Returns:
        bool: True se válido, False caso contrário
    """
    try:
        df = pd.read_csv(filepath)
        logger.info(f"Métricas carregadas: {len(df)} registros")
        logger.info(f"Colunas: {list(df.columns)}")
        
        # Verificar colunas obrigatórias  
        required_columns = ['date', 'account_id', 'campaign_id']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            logger.error(f"Colunas obrigatórias ausentes: {missing_columns}")
            return False
            
        # Estatísticas básicas
        logger.info(f"\nEstatísticas:")
        logger.info(f"Range de datas: {df['date'].min()} até {df['date'].max()}")
        logger.info(f"Contas únicas: {df['account_id'].nunique()}")
        logger.info(f"Campanhas únicas: {df['campaign_id'].nunique()}")
        
        # Mostrar primeiros registros
        logger.info("\nPrimeiros registros:")
        logger.info(df.head().to_string(index=False))
        
        return True
        
    except Exception as e:
        logger.error(f"Erro ao validar metrics.csv: {e}")
        return False

def main():
    """Função principal para validar todos os dados"""
    logger.info("Iniciando validação dos dados...")
    logger.info(f"Diretório atual: {os.getcwd()}")
    
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    users_file = os.path.join(data_dir, "users.csv")
    metrics_file = os.path.join(data_dir, "metrics.csv")
    
    # Verificar se arquivos existem
    if not os.path.exists(users_file):
        logger.error(f"Arquivo não encontrado: {users_file}")
        return
        
    if not os.path.exists(metrics_file):
        logger.error(f"Arquivo não encontrado: {metrics_file}")
        return
    
    # Validar dados
    logger.info("=" * 50)
    logger.info("VALIDANDO USUÁRIOS")
    logger.info("=" * 50)
    users_valid = validate_users_data(users_file)
    
    logger.info("\n" + "=" * 50)
    logger.info("VALIDANDO MÉTRICAS")  
    logger.info("=" * 50)
    metrics_valid = validate_metrics_data(metrics_file)
    
    # Resumo final
    logger.info("\n" + "=" * 50)
    logger.info("RESUMO DA VALIDAÇÃO")
    logger.info("=" * 50)
    logger.info(f"Users.csv: {'✓ Válido' if users_valid else '✗ Inválido'}")
    logger.info(f"Metrics.csv: {'✓ Válido' if metrics_valid else '✗ Inválido'}")
    
    if users_valid and metrics_valid:
        logger.info("✓ Todos os dados estão válidos!")
    else:
        logger.error("✗ Alguns dados precisam ser corrigidos.")

if __name__ == "__main__":
    main()
