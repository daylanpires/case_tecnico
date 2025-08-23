"""
Sistema de Autenticação e Métricas de Marketing Digital

API desenvolvida com FastAPI que oferece:
- Autenticação JWT segura com bcrypt
- Consulta de métricas com controle de permissões por role
- Paginação e filtros avançados
- Middleware CORS para integração frontend

Autor: Desenvolvido para processo seletivo
Versão: 1.0.0
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union

import bcrypt
import pandas as pd
from fastapi import FastAPI, HTTPException, Depends, Request, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === CONFIGURAÇÕES ===
# Configurações JWT - Em produção, usar variáveis de ambiente
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "k2v8Qw1n9Zp3s7Xy5Tg6Jr4Lm8Vb2Nc1Qw3Er5Ty7Ui9Op0As")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Limites de segurança
MAX_PAGE_SIZE = 1000
DEFAULT_PAGE_SIZE = 50

# Caminhos dos arquivos de dados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_CSV = os.path.abspath(os.path.join(BASE_DIR, "..", "data", "users.csv"))
METRICS_CSV = os.path.abspath(os.path.join(BASE_DIR, "..", "data", "metrics.csv"))

# === APLICAÇÃO FASTAPI ===
app = FastAPI(
    title="Sistema de Métricas de Marketing Digital",
    description="""
    API completa para autenticação e consulta de métricas de marketing digital.
    
    **Características principais:**
    - 🔐 Autenticação JWT com bcrypt
    - 👥 Controle de acesso por roles (admin/user)
    - 📊 Consulta de métricas com filtros e paginação
    - 🚀 Performance otimizada para grandes volumes de dados
    
    **Usuários de teste:**
    - admin/admin123 (acesso completo)
    - user/user123 (acesso limitado)
    """,
    version="1.0.0",
    contact={
        "name": "Equipe de Desenvolvimento",
        "email": "dev@empresa.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# === MIDDLEWARE ===
# Configuração CORS - Em produção, especificar origins exatos
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# === FUNÇÕES UTILITÁRIAS ===

def get_users() -> pd.DataFrame:
    """
    Carrega dados dos usuários do arquivo CSV com tratamento de erro robusto.
    
    Returns:
        pd.DataFrame: DataFrame contendo colunas 'username', 'password' e 'role'
        
    Raises:
        HTTPException: 
            - 500: Se arquivo não for encontrado ou houver erro de leitura
            - 500: Se estrutura do CSV for inválida
            
    Note:
        Em produção, considerar usar banco de dados ao invés de CSV
    """
    try:
        if not os.path.exists(USERS_CSV):
            logger.error(f"Arquivo de usuários não encontrado: {USERS_CSV}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Arquivo de configuração de usuários não encontrado"
            )
        
        df = pd.read_csv(USERS_CSV)
        
        # Validar estrutura esperada do CSV
        required_columns = {'username', 'password', 'role'}
        if not required_columns.issubset(df.columns):
            missing = required_columns - set(df.columns)
            logger.error(f"Colunas obrigatórias ausentes no CSV: {missing}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Estrutura de dados de usuários inválida"
            )
        
        logger.info(f"Carregados {len(df)} usuários do arquivo CSV")
        return df
        
    except pd.errors.EmptyDataError:
        logger.error("Arquivo de usuários está vazio")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Arquivo de usuários está vazio"
        )
    except pd.errors.ParserError as e:
        logger.error(f"Erro ao fazer parse do CSV de usuários: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Formato do arquivo de usuários inválido"
        )
    except Exception as e:
        logger.error(f"Erro inesperado ao ler usuários: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno do servidor"
        )

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha em texto plano corresponde ao hash bcrypt armazenado.
    
    Args:
        plain_password: Senha fornecida pelo usuário em texto plano
        hashed_password: Hash bcrypt armazenado no banco/CSV
        
    Returns:
        bool: True se a senha estiver correta, False caso contrário
        
    Note:
        Função segura contra timing attacks devido ao bcrypt
    """
    if not plain_password or not hashed_password:
        logger.warning("Tentativa de verificação de senha com parâmetros vazios")
        return False
        
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'), 
            hashed_password.encode('utf-8')
        )
    except (ValueError, TypeError) as e:
        logger.warning(f"Erro na verificação de senha: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado na verificação de senha: {e}")
        return False

def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """
    Autentica um usuário verificando credenciais contra o banco de dados.
    
    Args:
        username: Nome de usuário ou email
        password: Senha em texto plano
        
    Returns:
        dict: Dados do usuário {'email': str, 'role': str} se válido
        None: Se credenciais inválidas
        
    Raises:
        HTTPException: Se houver erro ao acessar dados dos usuários
        
    Security:
        - Usa bcrypt para verificação segura de senhas
        - Log de tentativas de autenticação para auditoria
        - Não vaza informações sobre existência de usuários
    """
    try:
        users_df = get_users()
        
        # Buscar usuário (case-insensitive para email)
        user_match = users_df[users_df['username'].str.lower() == username.lower()]
        
        if user_match.empty:
            logger.warning(f"Tentativa de login com usuário inexistente: {username}")
            return None
        
        user_data = user_match.iloc[0]
        
        # Verificar senha usando bcrypt
        if not verify_password(password, user_data['password']):
            logger.warning(f"Senha incorreta para usuário: {username}")
            return None
        
        # Autenticação bem-sucedida
        logger.info(f"Login bem-sucedido para usuário: {username} (role: {user_data['role']})")
        return {
            "email": user_data['username'],
            "role": user_data['role']
        }
        
    except HTTPException:
        # Re-raise HTTPExceptions (já tratadas)
        raise
    except Exception as e:
        logger.error(f"Erro inesperado na autenticação: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno durante autenticação"
        )

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Cria um token JWT assinado com os dados do usuário.
    
    Args:
        data: Dados para incluir no payload do token
        expires_delta: Tempo customizado de expiração (opcional)
        
    Returns:
        str: Token JWT assinado
        
    Raises:
        Exception: Se houver erro na criação do token
        
    Security:
        - Token expira automaticamente após tempo configurado
        - Inclui timestamp de expiração no payload
        - Usa algoritmo HS256 para assinatura
    """
    try:
        to_encode = data.copy()
        
        # Calcular tempo de expiração
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        # Adicionar expiração ao payload
        to_encode.update({
            "exp": int(expire.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),  # Issued at
            "type": "access_token"
        })
        
        # Criar e assinar token
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        
        logger.info(f"Token criado para usuário: {data.get('email')} (expira em: {expire})")
        return token
        
    except Exception as e:
        logger.error(f"Erro ao criar token JWT: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao gerar token de acesso"
        )

async def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Extrai e valida o usuário atual a partir do token JWT no header Authorization.
    
    Args:
        request: Objeto Request HTTP do FastAPI
        
    Returns:
        dict: Dados do usuário decodificados do token
            - email: Email/username do usuário
            - role: Role/papel do usuário (admin, user, etc)
            - exp: Timestamp de expiração
            - iat: Timestamp de criação
            
    Raises:
        HTTPException: 
            - 401: Token ausente, formato inválido, expirado ou corrompido
            
    Security:
        - Valida formato do header Authorization
        - Verifica assinatura do token
        - Valida expiração automaticamente via jose.jwt
    """
    # Extrair header Authorization
    auth_header = request.headers.get("Authorization")
    
    if not auth_header:
        logger.warning("Tentativa de acesso sem header Authorization")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acesso ausente",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not auth_header.startswith("Bearer "):
        logger.warning(f"Formato de Authorization header inválido: {auth_header[:20]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Formato do token inválido. Use: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Extrair token
    token = auth_header[7:]  # Remove "Bearer "
    
    try:
        # Decodificar e validar token
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],
            options={"verify_exp": True}  # Validar expiração
        )
        
        # Validar campos obrigatórios
        email = payload.get("email")
        role = payload.get("role")
        token_type = payload.get("type")
        
        if not email or not role:
            logger.warning("Token com campos obrigatórios ausentes")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido: dados insuficientes"
            )
        
        if token_type != "access_token":
            logger.warning(f"Tipo de token inválido: {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tipo de token inválido"
            )
        
        logger.debug(f"Token validado com sucesso para usuário: {email}")
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("Tentativa de acesso com token expirado")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado. Faça login novamente",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.JWTError as e:
        logger.warning(f"Token JWT inválido: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou corrompido",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"Erro inesperado na validação do token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erro interno na validação do token"
        )

# === ENDPOINTS DA API ===

@app.post("/login", 
          summary="Autenticação de usuário",
          description="Endpoint para login que retorna token JWT válido",
          response_description="Token de acesso JWT",
          tags=["Autenticação"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    **Autenticar usuário e obter token de acesso**
    
    Este endpoint autentica um usuário usando username/password e retorna 
    um token JWT que deve ser usado para acessar endpoints protegidos.
    
    **Processo de autenticação:**
    1. Valida credenciais contra base de usuários
    2. Verifica senha usando hash bcrypt seguro  
    3. Gera token JWT com dados do usuário e expiração
    4. Retorna token para uso em requisições subsequentes
    
    **Usuários de teste disponíveis:**
    - `admin` / `admin123` → Acesso completo (vê dados financeiros)
    - `user` / `user123` → Acesso limitado (sem dados sensíveis)
    
    **Como usar o token:**
    ```
    Authorization: Bearer <seu_token_aqui>
    ```
    
    **Segurança:**
    - Senhas verificadas com bcrypt (resistente a timing attacks)
    - Tokens expiram automaticamente em 60 minutos
    - Log de tentativas para auditoria
    """
    try:
        # Autenticar usuário
        user = authenticate_user(form_data.username, form_data.password)
        
        if not user:
            # Não revelar se é usuário ou senha inválida por segurança
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais inválidas",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Criar token de acesso
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "email": user["email"], 
                "role": user["role"]
            },
            expires_delta=access_token_expires
        )
        
        logger.info(f"Login bem-sucedido: {user['email']} (role: {user['role']})")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60  # em segundos
        }
        
    except HTTPException:
        # Re-raise HTTPExceptions (já tratadas)
        raise
    except Exception as e:
        logger.error(f"Erro inesperado no login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno no processo de autenticação"
        )

@app.get("/", 
         summary="Status da API",
         description="Endpoint de verificação de saúde da aplicação",
         tags=["Sistema"])
async def root():
    """
    **Verificar status da API**
    
    Endpoint de health check que confirma se a API está funcionando
    corretamente e fornece informações básicas da aplicação.
    
    **Retorna:**
    - Status operacional da API
    - Versão da aplicação
    - Timestamp atual (UTC)
    - Informações de configuração básicas
    """
    return {
        "message": "Sistema de Métricas de Marketing Digital - API Online",
        "status": "operational", 
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "documentation": "/docs",
        "health_check": "/health"
    }

@app.get("/health",
         summary="Health check detalhado", 
         description="Verificação detalhada de saúde da aplicação",
         tags=["Sistema"])
async def health_check():
    """
    **Health check detalhado da aplicação**
    
    Endpoint para monitoramento que verifica o status de todos os 
    componentes críticos da aplicação.
    """
    try:
        # Verificar acesso aos arquivos de dados
        files_status = {
            "users_csv": os.path.exists(USERS_CSV),
            "metrics_csv": os.path.exists(METRICS_CSV)
        }
        
        # Status geral
        overall_status = "healthy" if all(files_status.values()) else "degraded"
        
        return {
            "status": overall_status,
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": files_status,
                "jwt_auth": "operational",
                "api": "operational"
            },
            "uptime": "API funcionando normalmente"
        }
        
    except Exception as e:
        logger.error(f"Erro no health check: {e}")
        return {
            "status": "error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "Falha na verificação de saúde"
        }

@app.get("/protected",
         summary="Endpoint protegido de teste",
         description="Endpoint para testar autenticação JWT",
         tags=["Sistema"])
async def protected_route(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    **Endpoint protegido para teste de autenticação**
    
    Use este endpoint para verificar se seu token JWT está funcionando
    corretamente. Retorna informações do usuário autenticado.
    
    **Requer:** Token JWT válido no header Authorization
    """
    return {
        "message": f"🎉 Acesso autorizado para {current_user['email']}",
        "user_data": {
            "email": current_user['email'],
            "role": current_user['role'],
            "access_level": "Administrador" if current_user['role'] == "admin" else "Usuário comum"
        },
        "token_info": {
            "expires_at": datetime.fromtimestamp(current_user.get('exp', 0), timezone.utc).isoformat(),
            "issued_at": datetime.fromtimestamp(current_user.get('iat', 0), timezone.utc).isoformat()
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/metrics",
         summary="Consultar métricas de marketing",
         description="Endpoint principal para consulta de dados de métricas com filtros e paginação",
         tags=["Métricas"])
async def get_metrics(
    page: int = Query(1, ge=1, description="Número da página (inicia em 1)"),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description=f"Registros por página (máx: {MAX_PAGE_SIZE})"),
    start_date: Optional[str] = Query(None, description="Data inicial no formato YYYY-MM-DD", example="2024-01-01"),
    end_date: Optional[str] = Query(None, description="Data final no formato YYYY-MM-DD", example="2024-12-31"),  
    order_by: Optional[str] = Query(None, description="Campo para ordenação (date, clicks, impressions, etc)", example="date"),
    order_desc: bool = Query(False, description="Ordenação decrescente (padrão: crescente)"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    **Consultar métricas de marketing digital com controle de acesso**
    
    Este é o endpoint principal para consulta de métricas com sistema robusto 
    de filtros, paginação e controle de permissões baseado em roles.
    
    **🎯 Controle de Acesso por Role:**
    - **Admin:** Acesso completo incluindo dados financeiros (`cost_micros`)
    - **User:** Acesso limitado, campos sensíveis são ocultados
    
    **📊 Funcionalidades:**
    - **Paginação:** Navegue por grandes volumes de dados
    - **Filtros temporais:** Filtre por período específico  
    - **Ordenação:** Ordene por qualquer campo disponível
    - **Performance:** Otimizado para resposta rápida
    
    **📋 Campos disponíveis (varia por role):**
    - `date`: Data da métrica
    - `account_id`: ID da conta publicitária
    - `campaign_id`: ID da campanha (se disponível)
    - `clicks`: Número de cliques
    - `impressions`: Número de impressões  
    - `conversions`: Número de conversões
    - `interactions`: Número de interações
    - `cost_micros`: Custo em micros (**apenas admin**)
    
    **💡 Exemplos de uso:**
    - Listar primeiras 50 métricas: `GET /metrics`
    - Segunda página: `GET /metrics?page=2`  
    - Filtrar período: `GET /metrics?start_date=2024-01-01&end_date=2024-01-31`
    - Ordenar por cliques: `GET /metrics?order_by=clicks&order_desc=true`
    - Consulta complexa: `GET /metrics?page=1&limit=25&start_date=2024-01-01&order_by=cost_micros&order_desc=true`
    
    **🔒 Segurança:**
    - Requer token JWT válido
    - Controle de acesso baseado em role
    - Validação de parâmetros de entrada
    - Rate limiting implícito via paginação
    """
    try:
        # Calcular offset para paginação (baseada em página, não offset direto)
        offset = (page - 1) * limit
        
        # Carregar dados das métricas
        if not os.path.exists(METRICS_CSV):
            logger.error(f"Arquivo de métricas não encontrado: {METRICS_CSV}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Arquivo de dados de métricas não encontrado"
            )
        
        try:
            df = pd.read_csv(METRICS_CSV)
            logger.info(f"Carregadas {len(df)} métricas do arquivo CSV")
        except pd.errors.EmptyDataError:
            logger.warning("Arquivo de métricas está vazio")
            return {
                "data": [],
                "pagination": {
                    "page": page,
                    "limit": limit,  
                    "total_records": 0,
                    "total_pages": 0,
                    "has_next": False,
                    "has_previous": False
                },
                "filters_applied": {
                    "start_date": start_date,
                    "end_date": end_date,
                    "order_by": order_by,
                    "order_desc": order_desc
                },
                "user_access": {
                    "role": current_user.get('role'),
                    "restricted_fields": []
                }
            }
        except pd.errors.ParserError as e:
            logger.error(f"Erro ao fazer parse do CSV de métricas: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Formato do arquivo de métricas inválido"
            )
        
        # === APLICAR FILTROS ===
        original_count = len(df)
        
        # Filtro por data de início
        if start_date:
            try:
                df = df[df['date'] >= start_date]
                logger.debug(f"Filtro start_date aplicado: {len(df)} registros restantes")
            except (KeyError, TypeError) as e:
                logger.warning(f"Erro ao aplicar filtro start_date: {e}")
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Formato de data inicial inválido ou campo 'date' não encontrado"
                )
        
        # Filtro por data de fim  
        if end_date:
            try:
                df = df[df['date'] <= end_date]
                logger.debug(f"Filtro end_date aplicado: {len(df)} registros restantes")
            except (KeyError, TypeError) as e:
                logger.warning(f"Erro ao aplicar filtro end_date: {e}")
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Formato de data final inválido ou campo 'date' não encontrado"
                )
        
        # === APLICAR ORDENAÇÃO ===
        if order_by:
            if order_by in df.columns:
                try:
                    df = df.sort_values(by=order_by, ascending=not order_desc)
                    logger.debug(f"Ordenação aplicada por {order_by} ({'desc' if order_desc else 'asc'})")
                except Exception as e:
                    logger.warning(f"Erro ao ordenar por {order_by}: {e}")
                    # Continuar sem ordenação em caso de erro
            else:
                logger.warning(f"Campo de ordenação inválido: {order_by}. Campos disponíveis: {list(df.columns)}")
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Campo de ordenação '{order_by}' não existe. Campos disponíveis: {list(df.columns)}"
                )
        
        # === CONTROLE DE ACESSO ===
        restricted_fields = []
        if current_user.get("role") != "admin":
            # Remover campos sensíveis para usuários não-admin
            sensitive_fields = ["cost_micros"]
            fields_to_remove = [field for field in sensitive_fields if field in df.columns]
            
            if fields_to_remove:
                df = df.drop(columns=fields_to_remove)
                restricted_fields = fields_to_remove
                logger.info(f"Campos sensíveis removidos para usuário '{current_user.get('email')}': {fields_to_remove}")
        
        # === CALCULAR PAGINAÇÃO ===
        total_filtered = len(df)
        total_pages = (total_filtered + limit - 1) // limit  # Ceiling division
        
        # Validar página solicitada
        if page > total_pages and total_pages > 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Página {page} não existe. Total de páginas: {total_pages}"
            )
        
        # === APLICAR PAGINAÇÃO ===
        paginated_df = df.iloc[offset:offset + limit]
        
        # === PREPARAR RESPOSTA ===
        data = paginated_df.to_dict(orient="records")
        
        # Log da operação
        logger.info(f"Métricas retornadas: {len(data)} registros (página {page}/{total_pages}) "
                   f"para usuário {current_user.get('email')} (role: {current_user.get('role')})")
        
        return {
            "data": data,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_records": total_filtered,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_previous": page > 1,
                "showing": f"{offset + 1}-{min(offset + limit, total_filtered)} de {total_filtered}"
            },
            "filters_applied": {
                "start_date": start_date,
                "end_date": end_date, 
                "order_by": order_by,
                "order_desc": order_desc,
                "records_filtered": f"{total_filtered} de {original_count} registros"
            },
            "user_access": {
                "role": current_user.get('role'),
                "email": current_user.get('email'),
                "restricted_fields": restricted_fields,
                "access_level": "full" if not restricted_fields else "limited"
            }
        }
        
    except HTTPException:
        # Re-raise HTTPExceptions (já tratadas)
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao buscar métricas: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar consulta de métricas"
        )

# === STARTUP EVENT ===
@app.on_event("startup")
async def startup_event():
    """Evento executado na inicialização da aplicação."""
    logger.info("=== Sistema de Métricas de Marketing Digital ===")
    logger.info("API iniciada com sucesso!")
    logger.info(f"Versão: 1.0.0")
    logger.info(f"Ambiente: {'Desenvolvimento' if SECRET_KEY == 'k2v8Qw1n9Zp3s7Xy5Tg6Jr4Lm8Vb2Nc1Qw3Er5Ty7Ui9Op0As' else 'Produção'}")
    logger.info(f"Documentação disponível em: /docs")
    
    # Verificar arquivos críticos
    if not os.path.exists(USERS_CSV):
        logger.warning(f"⚠️  Arquivo de usuários não encontrado: {USERS_CSV}")
    else:
        logger.info(f"✅ Arquivo de usuários OK: {USERS_CSV}")
        
    if not os.path.exists(METRICS_CSV):
        logger.warning(f"⚠️  Arquivo de métricas não encontrado: {METRICS_CSV}")
    else:
        logger.info(f"✅ Arquivo de métricas OK: {METRICS_CSV}")

# === EXCEPTION HANDLERS ===
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handler para rotas não encontradas."""
    return {
        "error": "Endpoint não encontrado",
        "message": f"A rota '{request.url.path}' não existe",
        "available_endpoints": [
            "GET /",
            "GET /health", 
            "POST /login",
            "GET /protected",
            "GET /metrics",
            "GET /docs"
        ],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Handler para erros internos do servidor."""
    logger.error(f"Erro interno no endpoint {request.url.path}: {exc}")
    return {
        "error": "Erro interno do servidor",
        "message": "Ocorreu um erro inesperado. Tente novamente em alguns instantes",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "support": "Entre em contato com o suporte se o problema persistir"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Configuração para desenvolvimento
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )