from bcrypt import hashpw, gensalt, checkpw

def hash_password(password: str) -> str:
    """
    Gera um hash seguro para a senha fornecida.
    """
    if not password:
        raise ValueError("A senha não pode ser vazia.")
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verifica se a senha corresponde ao hash armazenado.
    """
    if not password or not hashed:
        return False
    return checkpw(password.encode('utf-8'), hashed.encode('utf-8'))