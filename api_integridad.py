"""API que verifica la integridad de lo que recibe, según el modo que pida el cliente.

    uvicorn api_integridad:app --port 8100

Cabeceras que espera en cada subida:
    X-Nombre    nombre con el que se guarda el archivo
    X-Modo      sha256 | hmac | ninguno
    X-Etiqueta  la etiqueta de integridad (hexadecimal)
"""
import hashlib
import hmac
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response

from secretos import CLAVE_COMPARTIDA

app = FastAPI()

ALMACEN = Path("almacen")
ALMACEN.mkdir(exist_ok=True)


@app.post("/upload")
async def subir(
    request: Request,
    x_nombre: str = Header(),
    x_modo: str = Header(),
    x_etiqueta: str = Header(default=""),
):
    datos = await request.body()

    if x_modo == "sha256":
        esperada = hashlib.sha256(datos).hexdigest()
    elif x_modo == "hmac":
        esperada = hmac.new(CLAVE_COMPARTIDA, datos, hashlib.sha256).hexdigest()
    else:
        esperada = None

    if esperada is not None and not hmac.compare_digest(esperada, x_etiqueta):
        raise HTTPException(
            status_code=400,
            detail=f"La etiqueta ({x_modo}) no coincide: el archivo fue alterado",
        )

    nombre = Path(x_nombre).name
    ALMACEN.mkdir(exist_ok=True)
    (ALMACEN / nombre).write_bytes(datos)
    return {"nombre": nombre, "bytes": len(datos), "verificado": x_modo if esperada else "no"}


@app.get("/files/{nombre}")
def bajar(nombre: str):
    ruta = ALMACEN / Path(nombre).name
    if not ruta.exists():
        raise HTTPException(status_code=404, detail="No existe")
    return Response(ruta.read_bytes(), media_type="application/octet-stream")
