"""
Teste básico para verificar se pytest funciona
"""

import pytest

def test_simple():
    """Teste simples para verificar se pytest está funcionando"""
    assert 1 + 1 == 2

def test_string():
    """Teste de string"""
    assert "hello" == "hello"

def test_list():
    """Teste de lista"""
    test_list = [1, 2, 3]
    assert len(test_list) == 3
    assert 2 in test_list

if __name__ == "__main__":
    pytest.main(["-v", __file__])
