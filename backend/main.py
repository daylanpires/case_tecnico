"""
API FastAPI para autenticação e consulta de métricas de marketing digital.
Desenvolvido para processo seletivo de engenheiro de software.
"""

import bcrypt
import pandas as pd
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware
import os

# Configurações JWT
SECRET_KEY = "k2v8Qw1n9Zp3s7Xy5Tg6Jr4Lm8Vb2Nc1Qw3Er5Ty7Ui9Op0As"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Caminhos dos arquivos CSV
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_CSV = os.path.join(BASE_DIR, "..", "data", "users.csv")
METRICS_CSV = os.path.join(BASE_DIR, "..", "data", "metrics.csv")

app = FastAPI(
    title="Métricas API",
    description="API para autenticação e consulta de métricas de marketing digital",
    version="1.0.0"
)

# Configuração CORS para desenvolvimento
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, especificar domínios exatos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_users():
    """
    Lê o arquivo CSV de usuários.
    
    Returns:
        DataFrame: DataFrame com os dados dos usuários
        
    Raises:
        HTTPException: Se o arquivo não puder ser lido
    """
    try:
        return pd.read_csv(USERS_CSV)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Arquivo users.csv não encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao ler users.csv: {e}")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha em texto plano corresponde ao hash.
    
    Args:
        plain_password: Senha em texto plano
        hashed_password: Hash da senha
        
    Returns:
        bool: True se a senha estiver correta
    """
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def authenticate_user(email: str, password: str) -> dict:
    """
    Autentica um usuário com email e senha.
    
    Args:
        email: Email do usuário
        password: Senha do usuário
        
    Returns:
        dict: Dados do usuário autenticado ou None se inválido
    """
    users = get_users()
    user = users[users['username'] == email]
    
    if user.empty:
        return None
        
    hashed_password = user.iloc[0]['password']
    if not verify_password(password, hashed_password):
        return None
        
    return {"email": email, "role": user.iloc[0]['role']}

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    """
    Cria um token JWT.
    
    Args:
        data: Dados para incluir no token
        expires_delta: Tempo de expiração customizado
        
    Returns:
        str: Token JWT
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request) -> dict:
    """
    Extrai e valida o usuário atual a partir do token JWT.
    
    Args:
        request: Request HTTP
        
    Returns:
        dict: Dados do usuário atual
        
    Raises:
        HTTPException: Se o token for inválido ou ausente
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou formato inválido")
        
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint de login que retorna um token JWT.
    
    Args:
        form_data: Dados do formulário (username e password)
        
    Returns:
        dict: Token JWT e tipo
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")
    
    access_token = create_access_token({"email": user["email"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def root():
    """Endpoint raiz para verificar se a API está funcionando."""
    return {"msg": "API de autenticação ativa!", "version": "1.0.0"}

@app.get("/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    """Endpoint protegido para testar autenticação."""
    return {"msg": f"Olá, {current_user['email']}! Seu cargo é {current_user['role']}"}

@app.get("/metrics")
def get_metrics(
    start_date: str = Query(None, description="Data inicial no formato YYYY-MM-DD"),
    end_date: str = Query(None, description="Data final no formato YYYY-MM-DD"),
    order_by: str = Query(None, description="Coluna para ordenação"),
    limit: int = Query(50, ge=1, le=1000, description="Limite de registros por página"),
    offset: int = Query(0, ge=0, description="Deslocamento dos registros (página)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint para consultar métricas com filtros, paginação e controle de acesso.
    
    Args:
        start_date: Data inicial do filtro
        end_date: Data final do filtro
        order_by: Coluna para ordenação
        limit: Número máximo de registros por página
        offset: Número de registros a pular (para paginação)
        current_user: Usuário autenticado (injetado automaticamente)
        
    Returns:
        dict: Dados paginados e total de registros
    """
    try:
        df = pd.read_csv(METRICS_CSV)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Arquivo metrics.csv não encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao ler metrics.csv: {e}")

    # Aplicar filtros de data
    if start_date:
        df = df[df['date'] >= start_date]
    if end_date:
        df = df[df['date'] <= end_date]

    # Aplicar ordenação
    if order_by and order_by in df.columns:
        df = df.sort_values(by=order_by)

    # Calcular total antes da paginação
    total = len(df)
    
    # Aplicar paginação
    df = df.iloc[offset:offset+limit]

    # Controle de acesso: ocultar cost_micros para usuários não-admin
    if current_user.get("role") != "admin" and "cost_micros" in df.columns:
        df = df.drop(columns=["cost_micros"])

    return {
        "data": df.to_dict(orient="records"),
        "total": total,
        "page_info": {
            "limit": limit,
            "offset": offset,
            "current_page": (offset // limit) + 1,
            "total_pages": (total + limit - 1) // limit
        }
    }