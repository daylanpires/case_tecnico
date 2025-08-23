#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para gerar hash de senhas usando bcrypt
Usado para criar senhas hashed para o arquivo users.csv

Uso:
    python hash_senhas.py

Saída:
    Lista de usuários com senhas hasheadas no formato CSV
    Exemplo: admin,$2b$12$abcd...
"""

import bcrypt
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """
    Gera hash bcrypt para uma senha
    
    Args:
        password (str): Senha em texto plano
        
    Returns:
        str: Senha hasheada em formato string
    """
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Erro ao hashear senha: {e}")
        raise

def main():
    """Função principal para gerar hashes das senhas"""
    # Senhas para hash (ajustar conforme necessário)
    senhas = {
        "admin": "admin123",
        "analyst": "analyst123", 
        "user1": "oeiruhn56146",
        "user2": "908ijofff"
    }
    
    logger.info("Gerando hashes de senhas...")
    
    for usuario, senha in senhas.items():
        try:
            hashed_password = hash_password(senha)
            print(f"{usuario},{hashed_password}")
            logger.info(f"Hash gerado para usuário: {usuario}")
        except Exception as e:
            logger.error(f"Erro ao processar usuário {usuario}: {e}")

if __name__ == "__main__":
    main()