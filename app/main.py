# app/main.py
import asyncio
import logging
from contextlib import asynccontextmanager
from . import logic
from fastapi import FastAPI
from .logging_config import setup_logging # IMPORTAMOS LA FUNCIÓN

setup_logging()
logger = logging.getLogger("app")

from contextlib import asynccontextmanager
from .routers import subscribers


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestiona el ciclo de vida de la aplicación.
    Ejecuta tareas de inicio y limpieza.
    """
    async def warmup_task_wrapper():
        try:
            logger.info("Iniciando tarea de calentamiento de conexiones en segundo plano...")
            await logic.warmup_connections()
            logger.info("Tarea de calentamiento de conexiones finalizada exitosamente.")
        except Exception as e:
     
            logger.error(f"La tarea de calentamiento de conexiones falló: {e}", exc_info=True)
    asyncio.create_task(warmup_task_wrapper())

    yield 


app = FastAPI(
    title="FastAPI Simple Subscribers EDUSOFT",
    version="0.1.0",
    lifespan=lifespan
)

# Incluye todas las rutas definidas en el archivo subscribers.py
app.include_router(subscribers.router)

# Este es el endpoint raíz, útil para una verificación rápida de que la API está viva.
@app.get("/")
def read_root():
    return {"Aplicacion": "Activa"}