# app/gunicorn_conf.py
import logging
import asyncio
from logging.config import dictConfig

from app.logging_config import LOGGING_CONFIG
from app import logic


_warmup_done = False

def on_starting(server):
    """
    Este hook se ejecuta una sola vez en el proceso maestro de Gunicorn
    antes de que los workers sean creados.
    """
    global _warmup_done
    
    # Configura el logging para el proceso maestro
    dictConfig(LOGGING_CONFIG)
    logger = logging.getLogger("app")
    
    if not _warmup_done:
        logger.info("PROCESO MAESTRO: Iniciando el calentamiento de conexiones...")
        try:
            # Ejecutamos la corutina de forma síncrona en el proceso maestro
            asyncio.run(logic.warmup_connections())
            logger.info("PROCESO MAESTRO: Calentamiento de conexiones finalizado exitosamente.")
        except Exception as e:
            logger.error(f"PROCESO MAESTRO: El calentamiento de conexiones falló: {e}", exc_info=True)
        
        _warmup_done = True

def post_fork(server, worker):
    """
    Este hook se ejecuta en cada worker justo después de que es creado.
    Aquí es donde configuramos el logging para cada worker.
    """
    dictConfig(LOGGING_CONFIG)
    logging.getLogger("gunicorn.error").info("Custom logging config cargada para el worker.")