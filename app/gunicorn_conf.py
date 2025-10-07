# app/gunicorn_conf.py
import logging
# CORRIGE ESTA LÍNEA
from app.logging_config import LOGGING_CONFIG
from logging.config import dictConfig

def on_starting(server):
    dictConfig(LOGGING_CONFIG)
    logging.getLogger("gunicorn.error").info("Custom logging config cargada")