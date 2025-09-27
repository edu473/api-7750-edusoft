# app/main.py

from fastapi import FastAPI
from .routers import subscribers
from .logging_config import setup_logging # IMPORTAMOS LA FUNCIÓN

# Llama a la función para configurar el logging al iniciar la app.
setup_logging()

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