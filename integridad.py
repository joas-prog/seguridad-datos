"""Ejercicio de integridad: hash y HMAC.

Completa cada función marcada con TODO y ejecuta este archivo para ver
qué autochequeos pasan:

    python integridad.py

Cuando pasen, prueba tus funciones contra el espía:

    python cliente_integridad.py sha256
"""
import hashlib
import hmac


def sha256_hex(datos):
    """SHA-256 de `datos` (bytes), escrito en hexadecimal."""
    # TODO: hashlib.sha256(...) y luego .hexdigest()
    raise NotImplementedError


def hmac_hex(clave, datos):
    """HMAC-SHA256 de `datos` con `clave` (ambos bytes), en hexadecimal."""
    # TODO: hmac.new(clave, datos, hashlib.sha256) y luego .hexdigest()
    raise NotImplementedError


def hmac_manual(clave, datos):
    """Lo mismo que hmac_hex, pero armado a mano con la fórmula, usando solo hashlib.sha256:

        HMAC(K, m) = SHA256( (K' ⊕ opad) + SHA256( (K' ⊕ ipad) + m ) )

    K' es la clave rellenada con ceros hasta 64 bytes (si es más larga, primero se
    reemplaza por su SHA-256). ipad es el byte 0x36 repetido 64 veces y opad es el byte
    0x5c repetido 64 veces. El + significa pegar bytes uno a continuación del otro.
    """
    # TODO: 1) prepara K'   2) haz XOR de cada byte con 0x36 y con 0x5c
    #       3) calcula el hash interno   4) calcula el hash externo con el resultado
    raise NotImplementedError


# ---------- Autochequeos ----------

def chequear(nombre, prueba):
    try:
        ok = prueba()
    except NotImplementedError:
        print(f"[ ] {nombre}: pendiente")
        return
    print(f"[{'x' if ok else '!'}] {nombre}" + ("" if ok else "  <- revisa esta"))


if __name__ == "__main__":
    vectores = [
        (b"Jefe", b"what do ya want for nothing?"),
        (b"clave-del-certamen-2026", b"La bandera es FLAG-ana-2026"),
        (b"k" * 100, b"una clave de mas de 64 bytes se reemplaza por su hash"),
    ]

    chequear("sha256_hex", lambda: sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    chequear("hmac_hex", lambda: hmac_hex(*vectores[0]) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    chequear("hmac_manual", lambda: all(
        hmac_manual(k, m) == hmac.new(k, m, hashlib.sha256).hexdigest() for k, m in vectores
    ))
