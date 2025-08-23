#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitários para autenticação e manipulação de senhas
Fornece funções seguras para hash e verificação de senhas usando bcrypt
"""

from bcrypt import hashpw, gensalt, checkpw
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """
    Gera um hash seguro para a senha fornecida usando bcrypt.
    
    Args:
        password (str): Senha em texto plano
        
    Returns:
        str: Hash da senha em formato string
        
    Raises:
        ValueError: Se a senha for vazia ou None
        Exception: Para outros erros durante o hash
    """
    if not password:
        raise ValueError("A senha não pode ser vazia.")
        
    try:
        # Gerar salt e hash da senha
        salt = gensalt()
        hashed = hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Erro ao gerar hash da senha: {e}")
        raise Exception(f"Erro interno ao processar senha: {e}")

def verify_password(password: str, hashed: str) -> bool:
    """
    Verifica se a senha corresponde ao hash armazenado.
    
    Args:
        password (str): Senha em texto plano para verificar
        hashed (str): Hash da senha armazenado
        
    Returns:
        bool: True se a senha corresponder, False caso contrário
    """
    if not password or not hashed:
        logger.warning("Tentativa de verificação com senha ou hash vazio")
        return False
        
    try:
        return checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        logger.error(f"Erro ao verificar senha: {e}")
        return False

def is_strong_password(password: str) -> tuple[bool, Optional[str]]:
    """
    Verifica se uma senha atende aos critérios de segurança básicos.
    
    Args:
        password (str): Senha para validar
        
    Returns:
        tuple[bool, Optional[str]]: (é_válida, mensagem_erro)
    """
    if not password:
        return False, "Senha não pode ser vazia"
        
    if len(password) < 6:
        return False, "Senha deve ter pelo menos 6 caracteres"
        
    # Adicionar mais validações conforme necessário
    # has_upper = any(c.isupper() for c in password)
    # has_lower = any(c.islower() for c in password) 
    # has_digit = any(c.isdigit() for c in password)
    
    return True, None