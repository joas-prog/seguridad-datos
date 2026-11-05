"""Sube el mismo secreto de dos formas: en claro, y cifrado en el cliente.

    python cliente.py
"""
import httpx
from cryptography.fernet import Fernet, InvalidToken

API = "http://127.0.0.1:8180"  # 8180 = pasa por el espía; usa 8100 para ir directo a la API
SECRETO = b"La bandera es FLAG-ana-2026: nadie debe leer esto."

clave = Fernet.generate_key()  # la clave se queda aquí: nunca se sube
fernet = Fernet(clave)


def subir(nombre, datos):
    r = httpx.post(f"{API}/upload", files={"archivo": (nombre, datos)})
    print(f"Subido {nombre}: {r.json()}")


def bajar(nombre):
    return httpx.get(f"{API}/files/{nombre}").content


subir("secreto.txt", SECRETO)
subir("secreto.enc", fernet.encrypt(SECRETO))

print("\nDescargando de vuelta lo que guardó el servidor:")
print("  secreto.txt ->", bajar("secreto.txt").decode())
try:
    print("  secreto.enc ->", fernet.decrypt(bajar("secreto.enc")).decode())
except InvalidToken:
    print("  secreto.enc -> ¡InvalidToken! El cifrado detectó que alguien lo alteró.")
