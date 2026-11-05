"""Solución del ejercicio de integridad. Mírala solo cuando hayas intentado la tuya."""
import hashlib
import hmac


def sha256_hex(datos):
    return hashlib.sha256(datos).hexdigest()


def hmac_hex(clave, datos):
    return hmac.new(clave, datos, hashlib.sha256).hexdigest()


def hmac_manual(clave, datos):
    bloque = 64
    if len(clave) > bloque:
        clave = hashlib.sha256(clave).digest()
    clave = clave.ljust(bloque, b"\x00")
    ipad = bytes(b ^ 0x36 for b in clave)
    opad = bytes(b ^ 0x5C for b in clave)
    interno = hashlib.sha256(ipad + datos).digest()
    return hashlib.sha256(opad + interno).hexdigest()
