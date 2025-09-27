# app/logging_config.py
import logging
from logging.config import dictConfig

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",  # Enviar logs a la salida estándar
        },
    },
    "loggers": {
        "": {  # Logger raíz
            "handlers": ["default"],
            "level": "INFO", # Nivel mínimo de logs a mostrar (INFO, DEBUG, WARN, etc.)
            "propagate": False,
        },
        "uvicorn.error": {
            "level": "INFO",
        },
        "uvicorn.access": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

def setup_logging():
    """Aplica la configuración de logging."""
    dictConfig(LOGGING_CONFIG)