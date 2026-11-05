"""API mínima para subir y bajar archivos. Guarda todo tal cual lo recibe, sin mirar el contenido.

    uvicorn api_archivos:app --port 8100
"""
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import Response

app = FastAPI()

ALMACEN = Path("almacen")
ALMACEN.mkdir(exist_ok=True)


@app.post("/upload")
async def subir(archivo: UploadFile):
    datos = await archivo.read()
    nombre = Path(archivo.filename).name
    (ALMACEN / nombre).write_bytes(datos)
    return {"nombre": nombre, "bytes": len(datos)}


@app.get("/files/{nombre}")
def bajar(nombre: str):
    ruta = ALMACEN / Path(nombre).name
    if not ruta.exists():
        raise HTTPException(status_code=404, detail="No existe")
    return Response(ruta.read_bytes(), media_type="application/octet-stream")
