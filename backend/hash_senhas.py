import bcrypt

senhas = {
    "user1": "oeiruhn56146",
    "user2": "908ijofff"
}

for usuario, senha in senhas.items():
    hashed = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    print(f"{usuario},{hashed.decode()}")