# app/main.py

from fastapi import FastAPI
from .logging_config import setup_logging # IMPORTAMOS LA FUNCIÓN

setup_logging()

from contextlib import asynccontextmanager
from .routers import subscribers


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Código que se ejecuta ANTES de que la aplicación empiece a aceptar peticiones
    # Creamos una tarea en segundo plano para no bloquear el inicio.
    asyncio.create_task(logic.warmup_connections())
    
    yield  # La aplicación se ejecuta aquí

# Crea la instancia principal de la aplicación FastAPI.
# Los títulos y versiones aparecerán en la documentación de Swagger.
app = FastAPI(
    title="FastAPI Simple Subscribers EDUSOFT",
    version="0.1.0"
)

# Incluye todas las rutas definidas en el archivo subscribers.py
app.include_router(subscribers.router)

# Este es el endpoint raíz, útil para una verificación rápida de que la API está viva.
@app.get("/")
def read_root():
    return {"Aplicacion": "Activa"}