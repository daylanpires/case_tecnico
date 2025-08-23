#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste simples da API FastAPI
Script para verificar se o FastAPI está funcionando corretamente

Uso:
    uvicorn teste:app --reload --port 8001
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Criar aplicação FastAPI
app = FastAPI(
    title="API Teste", 
    description="API simples para testes",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Endpoint raiz para verificação de saúde da API"""
    logger.info("Endpoint raiz acessado")
    return {
        "message": "API de teste ativa",
        "status": "healthy",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Endpoint de verificação de saúde"""
    return {
        "status": "healthy",
        "timestamp": "2024",
        "service": "FastAPI Test"
    }