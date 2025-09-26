# app/main.py

from fastapi import FastAPI
from .routers import subscribers

# Crea la instancia principal de la aplicación FastAPI.
# Los títulos y versiones aparecerán en la documentación de Swagger.
app = FastAPI(
    title="FastAPI Simple Subscribers EDUSOFT", # [cite: 2]
    version="0.1.0" # [cite: 3]
)

# Incluye todas las rutas definidas en el archivo subscribers.py
app.include_router(subscribers.router)

# Este es el endpoint raíz, útil para una verificación rápida de que la API está viva.
@app.get("/")
def read_root():
    return {"Hello": "World"}