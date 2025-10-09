# app/main.py

from fastapi import FastAPI
from .logging_config import setup_logging
from .routers import subscribers

setup_logging()

app = FastAPI(
    title="FastAPI Simple Subscribers EDUSOFT",
    version="0.1.0"
)

app.include_router(subscribers.router)


@app.get("/")
def read_root():
    return {"Aplicacion": "Activa"}