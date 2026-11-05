"""Cliente del ejercicio de integridad: sube el secreto con tres tipos de protección.

    python cliente_integridad.py sha256     adjunta un hash del archivo
    python cliente_integridad.py hmac       adjunta un HMAC con la clave compartida
    python cliente_integridad.py fernet     cifra y firma con Fernet

Agrega --solucion para usar solucion_integridad.py en lugar de tu integridad.py.
"""
import sys

import httpx
from cryptography.fernet import Fernet, InvalidToken

from secretos import CLAVE_COMPARTIDA

if "--solucion" in sys.argv:
    import solucion_integridad as integridad
else:
    import integridad

API = "http://127.0.0.1:8180"  # 8180 = pasa por el espía; usa 8100 para ir directo a la API
SECRETO = b"La bandera es FLAG-ana-2026: nadie debe leer esto."
MODOS = ("sha256", "hmac", "fernet")


def subir(nombre, datos, modo, etiqueta):
    cabeceras = {"X-Nombre": nombre, "X-Modo": modo, "X-Etiqueta": etiqueta}
    r = httpx.post(f"{API}/upload", content=datos, headers=cabeceras)
    try:
        cuerpo = r.json()
        detalle = cuerpo.get("detail") or cuerpo
    except ValueError:
        detalle = r.text
    print(f"Servidor responde {r.status_code}: {detalle}")
    return r.status_code == 200


def bajar(nombre):
    return httpx.get(f"{API}/files/{nombre}").content


def main(modo):
    if modo == "sha256":
        if subir("secreto.txt", SECRETO, "sha256", integridad.sha256_hex(SECRETO)):
            print("Lo que quedó guardado:", bajar("secreto.txt").decode())
    elif modo == "hmac":
        etiqueta = integridad.hmac_hex(CLAVE_COMPARTIDA, SECRETO)
        if subir("secreto.txt", SECRETO, "hmac", etiqueta):
            print("Lo que quedó guardado:", bajar("secreto.txt").decode())
    else:
        fernet = Fernet(Fernet.generate_key())
        subir("secreto.enc", fernet.encrypt(SECRETO), "ninguno", "")
        try:
            print("Lo que quedó guardado:", fernet.decrypt(bajar("secreto.enc")).decode())
        except InvalidToken:
            print("¡InvalidToken! El cifrado detectó que alguien lo alteró.")


if __name__ == "__main__":
    modos = [a for a in sys.argv[1:] if a in MODOS]
    if not modos:
        sys.exit("Uso: python cliente_integridad.py sha256 | hmac | fernet [--solucion]")
    main(modos[0])
