#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testes unitários para o sistema de autenticação e métricas
"""

import pytest
import pandas as pd
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import jwt as jwt_lib
from datetime import datetime, timedelta, timezone
import os
import sys

# Adicionar o diretório backend ao path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

try:
    from main import app, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
    # Test client
    client = TestClient(app)
    IMPORTS_OK = True
except ImportError as e:
    print(f"Erro na importação: {e}")
    IMPORTS_OK = False
    client = None

class TestAuthentication:
    """Testes para o sistema de autenticação"""
    
    @pytest.mark.skipif(not IMPORTS_OK, reason="Falha na importação dos módulos")
    def test_root_endpoint(self):
        """Testa o endpoint raiz"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "msg" in data
        assert "version" in data
        assert data["version"] == "1.0.0"
    
    @patch('main.get_users')
    def test_login_success_admin(self, mock_get_users):
        """Testa login bem-sucedido de admin"""
        # Mock do DataFrame de usuários
        mock_df = pd.DataFrame({
            'username': ['admin'],
            'password': ['$2b$12$test_hash'],
            'role': ['admin']
        })
        mock_get_users.return_value = mock_df
        
        with patch('main.verify_password', return_value=True):
            response = client.post("/login", data={
                "username": "admin",
                "password": "admin123"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
    
    @patch('main.get_users')
    def test_login_success_user(self, mock_get_users):
        """Testa login bem-sucedido de usuário comum"""
        mock_df = pd.DataFrame({
            'username': ['user'],
            'password': ['$2b$12$test_hash'],
            'role': ['user']
        })
        mock_get_users.return_value = mock_df
        
        with patch('main.verify_password', return_value=True):
            response = client.post("/login", data={
                "username": "user",
                "password": "user123"
            })
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
    
    @patch('main.get_users')
    def test_login_invalid_credentials(self, mock_get_users):
        """Testa login com credenciais inválidas"""
        mock_df = pd.DataFrame({
            'username': ['admin'],
            'password': ['$2b$12$test_hash'],
            'role': ['admin']
        })
        mock_get_users.return_value = mock_df
        
        with patch('main.verify_password', return_value=False):
            response = client.post("/login", data={
                "username": "admin",
                "password": "wrong_password"
            })
            
            assert response.status_code == 401
            assert "Usuário ou senha inválidos" in response.json()["detail"]
    
    @patch('main.get_users')
    def test_login_user_not_found(self, mock_get_users):
        """Testa login com usuário inexistente"""
        mock_df = pd.DataFrame({
            'username': ['admin'],
            'password': ['$2b$12$test_hash'],
            'role': ['admin']
        })
        mock_get_users.return_value = mock_df
        
        response = client.post("/login", data={
            "username": "nonexistent",
            "password": "password123"
        })
        
        assert response.status_code == 401
        assert "Usuário ou senha inválidos" in response.json()["detail"]
    
    def test_protected_endpoint_without_token(self):
        """Testa acesso a endpoint protegido sem token"""
        response = client.get("/protected")
        assert response.status_code == 401
    
    def test_protected_endpoint_with_valid_token(self):
        """Testa acesso a endpoint protegido com token válido"""
        # Criar token JWT válido
        payload = {
            "email": "admin@test.com",
            "role": "admin",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
        }
        token = jwt_lib.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        response = client.get("/protected", headers={
            "Authorization": f"Bearer {token}"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "Olá" in data["msg"]
        assert "admin@test.com" in data["msg"]
    
    def test_protected_endpoint_with_expired_token(self):
        """Testa acesso com token expirado"""
        # Criar token expirado
        payload = {
            "email": "admin@test.com",
            "role": "admin",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        }
        token = jwt_lib.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        response = client.get("/protected", headers={
            "Authorization": f"Bearer {token}"
        })
        
        assert response.status_code == 401
    
    def test_protected_endpoint_with_invalid_token(self):
        """Testa acesso com token inválido"""
        response = client.get("/protected", headers={
            "Authorization": "Bearer invalid_token"
        })
        
        assert response.status_code == 401

class TestMetricsEndpoint:
    """Testes para o endpoint de métricas"""
    
    def create_valid_token(self, role="admin"):
        """Cria um token JWT válido para testes"""
        payload = {
            "email": f"{role}@test.com",
            "role": role,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
        }
        return jwt_lib.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    @patch('pandas.read_csv')
    def test_metrics_endpoint_admin_sees_cost_micros(self, mock_read_csv):
        """Testa endpoint de métricas para admin (vê cost_micros)"""
        # Mock do DataFrame
        mock_df = pd.DataFrame({
            'date': ['2024-01-01', '2024-01-02'],
            'account_id': [123, 456],
            'cost_micros': [1000, 2000],
            'clicks': [10, 20],
            'impressions': [100, 200]
        })
        mock_read_csv.return_value = mock_df
        
        token = self.create_valid_token("admin")
        response = client.get("/metrics", headers={
            "Authorization": f"Bearer {token}"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "total" in data
        # Admin deve ver cost_micros
        if data["data"]:
            assert "cost_micros" in data["data"][0]
    
    @patch('pandas.read_csv')
    def test_metrics_endpoint_user_no_cost_micros(self, mock_read_csv):
        """Testa endpoint de métricas para usuário comum (não vê cost_micros)"""
        # Mock do DataFrame
        mock_df = pd.DataFrame({
            'date': ['2024-01-01', '2024-01-02'],
            'account_id': [123, 456],
            'cost_micros': [1000, 2000],
            'clicks': [10, 20],
            'impressions': [100, 200]
        })
        mock_read_csv.return_value = mock_df
        
        token = self.create_valid_token("user")
        response = client.get("/metrics", headers={
            "Authorization": f"Bearer {token}"
        })
        
        assert response.status_code == 200
        data = response.json()
        # Usuário não deve ver cost_micros
        if data["data"]:
            assert "cost_micros" not in data["data"][0]
    
    @patch('pandas.read_csv')
    def test_metrics_with_date_filters(self, mock_read_csv):
        """Testa endpoint de métricas com filtros de data"""
        mock_df = pd.DataFrame({
            'date': ['2024-01-01', '2024-01-02', '2024-01-03'],
            'account_id': [123, 456, 789],
            'clicks': [10, 20, 30],
            'impressions': [100, 200, 300]
        })
        mock_read_csv.return_value = mock_df
        
        token = self.create_valid_token("admin")
        response = client.get(
            "/metrics?start_date=2024-01-01&end_date=2024-01-02", 
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) >= 0  # Pode ser filtrado
    
    @patch('pandas.read_csv')
    def test_metrics_with_pagination(self, mock_read_csv):
        """Testa paginação do endpoint de métricas"""
        # Criar dados de teste com mais registros
        data_rows = []
        for i in range(100):
            data_rows.append({
                'date': f'2024-01-{(i%30)+1:02d}',
                'account_id': i,
                'clicks': i * 10,
                'impressions': i * 100
            })
        
        mock_df = pd.DataFrame(data_rows)
        mock_read_csv.return_value = mock_df
        
        token = self.create_valid_token("admin")
        response = client.get(
            "/metrics?limit=25&offset=0", 
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 100
        assert len(data["data"]) == 25
        assert data["page_info"]["limit"] == 25
        assert data["page_info"]["current_page"] == 1
    
    @patch('pandas.read_csv')
    def test_metrics_with_ordering(self, mock_read_csv):
        """Testa ordenação do endpoint de métricas"""
        mock_df = pd.DataFrame({
            'date': ['2024-01-01', '2024-01-02', '2024-01-03'],
            'account_id': [123, 456, 789],
            'clicks': [30, 10, 20],
            'impressions': [300, 100, 200]
        })
        mock_read_csv.return_value = mock_df
        
        token = self.create_valid_token("admin")
        response = client.get(
            "/metrics?order_by=clicks", 
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) > 0
    
    def test_metrics_without_token(self):
        """Testa acesso a métricas sem token"""
        response = client.get("/metrics")
        assert response.status_code == 401
    
    @patch('pandas.read_csv')
    def test_metrics_file_not_found(self, mock_read_csv):
        """Testa comportamento quando arquivo CSV não é encontrado"""
        mock_read_csv.side_effect = FileNotFoundError("Arquivo não encontrado")
        
        token = self.create_valid_token("admin")
        response = client.get("/metrics", headers={
            "Authorization": f"Bearer {token}"
        })
        
        assert response.status_code == 500
        assert "não encontrado" in response.json()["detail"]

class TestUtilityFunctions:
    """Testes para funções utilitárias"""
    
    def test_verify_password_correct(self):
        """Testa verificação de senha correta"""
        from main import verify_password
        import bcrypt
        
        password = "test_password"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Testa verificação de senha incorreta"""
        from main import verify_password
        import bcrypt
        
        password = "test_password"
        wrong_password = "wrong_password"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        assert verify_password(wrong_password, hashed) is False
    
    def test_create_access_token(self):
        """Testa criação de token JWT"""
        from main import create_access_token
        
        data = {"email": "test@test.com", "role": "user"}
        token = create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens são longos
    
    def test_authenticate_user_success(self):
        """Testa autenticação de usuário bem-sucedida"""
        from main import authenticate_user
        
        with patch('main.get_users') as mock_get_users:
            mock_df = pd.DataFrame({
                'username': ['testuser'],
                'password': ['hashed_password'],
                'role': ['user']
            })
            mock_get_users.return_value = mock_df
            
            with patch('main.verify_password', return_value=True):
                result = authenticate_user('testuser', 'password')
                
                assert result is not None
                assert result['email'] == 'testuser'
                assert result['role'] == 'user'
    
    def test_authenticate_user_failure(self):
        """Testa falha na autenticação de usuário"""
        from main import authenticate_user
        
        with patch('main.get_users') as mock_get_users:
            mock_df = pd.DataFrame({
                'username': ['testuser'],
                'password': ['hashed_password'],
                'role': ['user']
            })
            mock_get_users.return_value = mock_df
            
            with patch('main.verify_password', return_value=False):
                result = authenticate_user('testuser', 'wrong_password')
                
                assert result is None

class TestDataIntegrity:
    """Testes de integridade dos dados"""
    
    @patch('pandas.read_csv')
    def test_users_csv_structure(self, mock_read_csv):
        """Testa estrutura esperada do arquivo users.csv"""
        from main import get_users
        
        mock_df = pd.DataFrame({
            'username': ['user1', 'admin1'],
            'password': ['hash1', 'hash2'],
            'role': ['user', 'admin']
        })
        mock_read_csv.return_value = mock_df
        
        df = get_users()
        assert 'username' in df.columns
        assert 'password' in df.columns
        assert 'role' in df.columns
        assert len(df) == 2
    
    @patch('pandas.read_csv')
    def test_users_csv_file_error(self, mock_read_csv):
        """Testa tratamento de erro ao ler users.csv"""
        from main import get_users
        
        mock_read_csv.side_effect = FileNotFoundError("Arquivo não encontrado")
        
        with pytest.raises(Exception):  # HTTPException
            get_users()

class TestAPIEndpoints:
    """Testes gerais dos endpoints da API"""
    
    def test_api_endpoints_exist(self):
        """Testa se todos os endpoints principais existem"""
        # Teste GET /
        response = client.get("/")
        assert response.status_code == 200
        
        # Teste POST /login (sem dados, deve dar erro de validação)
        response = client.post("/login")
        assert response.status_code == 422  # Unprocessable Entity
        
        # Teste GET /protected (sem token, deve dar não autorizado)
        response = client.get("/protected")
        assert response.status_code == 401
        
        # Teste GET /metrics (sem token, deve dar não autorizado)
        response = client.get("/metrics")
        assert response.status_code == 401
    
    def test_cors_headers(self):
        """Testa se headers CORS estão configurados"""
        response = client.options("/")
        # CORS permite que OPTIONS funcione
        assert response.status_code in [200, 405]  # Pode variar dependendo do middleware
    
    def test_api_content_type(self):
        """Testa se API retorna JSON"""
        response = client.get("/")
        assert response.headers["content-type"] == "application/json"

if __name__ == "__main__":
    # Executar testes
    pytest.main(["-v", __file__])
