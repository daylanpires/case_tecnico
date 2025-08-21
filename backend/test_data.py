import pandas as pd
import os

usuarios = pd.read_csv("data/users.csv")
metrics = pd.read_csv("data/metrics.csv")

print("Usuarios:")
print(usuarios.head())

print("\nMétricas:")
print(metrics.head())
print(os.getcwd())
