"""Hombre en el medio mínimo: se pone entre el cliente y la API y muestra lo que pasa.

    python espia.py                          solo mira (ataque pasivo)
    python espia.py --modificar              además altera lo que se sube (ataque activo)
    python espia.py --modificar --recalcular además recalcula el hash de la cabecera X-Etiqueta

Solo usa la librería estándar. Funciona con HTTP; para HTTPS haría falta un proxy
que termine el TLS (como mitmproxy).
"""
import hashlib
import socket
import sys
import threading

ESCUCHA = ("127.0.0.1", 8180)
DESTINO = ("127.0.0.1", 8100)
MODIFICAR = "--modificar" in sys.argv
RECALCULAR = "--recalcular" in sys.argv


def leer_peticion(conexion):
    datos = b""
    while b"\r\n\r\n" not in datos:
        trozo = conexion.recv(4096)
        if not trozo:
            return None, None
        datos += trozo
    cabecera, _, cuerpo = datos.partition(b"\r\n\r\n")
    largo = 0
    for linea in cabecera.split(b"\r\n")[1:]:
        if linea.lower().startswith(b"content-length:"):
            largo = int(linea.split(b":")[1])
    while len(cuerpo) < largo:
        trozo = conexion.recv(4096)
        if not trozo:
            break
        cuerpo += trozo
    return cabecera, cuerpo


def alterar(cuerpo):
    cuerpo = cuerpo.replace(b"FLAG", b"HACK")  # texto en claro: se cambia sin dejar rastro
    i = cuerpo.find(b"gAAAAA")  # inicio de un token de Fernet
    if i >= 0:  # archivo cifrado: basta cambiar un solo carácter
        j = i + 40
        nuevo = b"B" if cuerpo[j:j + 1] == b"A" else b"A"
        cuerpo = cuerpo[:j] + nuevo + cuerpo[j + 1:]
    return cuerpo


def recalcular_etiqueta(cabecera, cuerpo):
    """Cambia la etiqueta X-Etiqueta por el SHA-256 del cuerpo ya alterado."""
    nueva = hashlib.sha256(cuerpo).hexdigest().encode()
    lineas = []
    for linea in cabecera.split(b"\r\n"):
        if linea.lower().startswith(b"x-etiqueta:"):
            linea = linea.split(b":")[0] + b": " + nueva
        lineas.append(linea)
    return b"\r\n".join(lineas)


def mostrar(titulo, cabecera, cuerpo):
    print(f"\n──── {titulo} ────")
    lineas = cabecera.split(b"\r\n")
    print(lineas[0].decode())
    for linea in lineas[1:]:
        if linea.lower().startswith(b"x-"):
            print(linea.decode())
    if cuerpo:
        print(cuerpo.decode("utf-8", errors="replace").strip())


def atender(cliente):
    cabecera, cuerpo = leer_peticion(cliente)
    if cabecera is None:
        cliente.close()
        return
    if cuerpo:
        mostrar("INTERCEPTADO", cabecera, cuerpo)
        if MODIFICAR:
            cuerpo = alterar(cuerpo)
            if RECALCULAR:
                cabecera = recalcular_etiqueta(cabecera, cuerpo)
            mostrar("SE REENVÍA ALTERADO", cabecera, cuerpo)
    else:
        mostrar("INTERCEPTADO", cabecera, b"")

    lineas = [l for l in cabecera.split(b"\r\n") if not l.lower().startswith(b"connection:")]
    cabecera = b"\r\n".join(lineas) + b"\r\nConnection: close"
    with socket.create_connection(DESTINO) as servidor:
        servidor.sendall(cabecera + b"\r\n\r\n" + cuerpo)
        while True:
            datos = servidor.recv(4096)
            if not datos:
                break
            cliente.sendall(datos)
    cliente.close()


def main():
    sys.stdout.reconfigure(line_buffering=True)
    with socket.socket() as escucha:
        escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        escucha.bind(ESCUCHA)
        escucha.listen()
        modo = "ACTIVO (modifica lo que sube)" if MODIFICAR else "pasivo (solo mira)"
        print(f"Espía {modo}: {ESCUCHA[0]}:{ESCUCHA[1]} → {DESTINO[0]}:{DESTINO[1]}")
        while True:
            cliente, _ = escucha.accept()
            threading.Thread(target=atender, args=(cliente,), daemon=True).start()


if __name__ == "__main__":
    main()
