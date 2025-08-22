print("Iniciando backend.auth...")

try:
    import bcrypt
    import pandas as pd
    from fastapi import FastAPI, HTTPException, Depends, Request, Query
    from fastapi.security import OAuth2PasswordRequestForm
    from jose import jwt, JWTError
    from datetime import datetime, timedelta, timezone

    SECRET_KEY = "k2v8Qw1n9Zp3s7Xy5Tg6Jr4Lm8Vb2Nc1Qw3Er5Ty7Ui9Op0As"  # Chave secreta para JWT
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60

    app = FastAPI()

    def get_users():
        try:
            print("Tentando ler o arquivo CSV...")
            df = pd.read_csv("c:/Users/dayla/Desktop/case_tecnico/data/users.csv")
            print("Arquivo CSV lido com sucesso!")
            return df
        except Exception as e:
            print("Erro ao ler users.csv:", e)
            raise

    def verify_password(plain_password, hashed_password):
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

    def authenticate_user(email: str, password: str):
        users = get_users()
        user = users[users['username'] == email]
        if user.empty:
            return None
        hashed_password = user.iloc[0]['password']
        if not verify_password(password, hashed_password):
            return None
        return {"email": email, "role": user.iloc[0]['role']}

    def create_access_token(data: dict, expires_delta: timedelta = None):
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": int(expire.timestamp())})  # Corrigido: exp como timestamp inteiro
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    async def get_current_user(request: Request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Token ausente")
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Token inválido ou expirado")

    @app.post("/login")
    def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")
        access_token = create_access_token({"email": user["email"], "role": user["role"]})
        return {"access_token": access_token, "token_type": "bearer"}

    @app.get("/")
    def root():
        return {"msg": "API de autenticação ativa!"}

    @app.get("/protected")
    def protected_route(current_user: dict = Depends(get_current_user)):
        return {"msg": f"Olá, {current_user['email']}! Seu cargo é {current_user['role']}"}

    @app.post("/soma")
    def soma(valores: dict):
        return {"resultado": valores["a"] + valores["b"]}

    @app.get("/metrics")
    def get_metrics(
        start_date: str = Query(None, description="Data inicial no formato YYYY-MM-DD"),
        end_date: str = Query(None, description="Data final no formato YYYY-MM-DD"),
        order_by: str = Query(None, description="Coluna para ordenação"),
        current_user: dict = Depends(get_current_user)
    ):
        try:
            df = pd.read_csv("c:/Users/dayla/Desktop/case_tecnico/data/metrics.csv")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erro ao ler metrics.csv: {e}")

        # Filtro por data, se informado
        if start_date:
            df = df[df['date'] >= start_date]
        if end_date:
            df = df[df['date'] <= end_date]

        # Ordenação, se informado
        if order_by and order_by in df.columns:
            df = df.sort_values(by=order_by)

        # Oculta cost_micros para não-admins
        if current_user.get("role") != "admin" and "cost_micros" in df.columns:
            df = df.drop(columns=["cost_micros"])

        return df.to_dict(orient="records")
except Exception as e:
    print("Erro fatal ao importar ou executar backend.auth:", e)
    raise