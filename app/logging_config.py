# app/logging_config.py
import logging
from logging.config import dictConfig

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": True,
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
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        # --- MODIFICACIÓN ---
        
        # 1. Logger específico para nuestra aplicación.
        #    Mostrará mensajes de nivel INFO y superiores.
        "app": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },

        # 2. Silenciamos los loggers de librerías de terceros.
        #    Solo mostrarán mensajes si ocurre una advertencia (WARNING) o un error.
        "ncclient": {
            "handlers": ["default"],
            "level": "WARNING",
            "propagate": False,
        },
        "pysros": {
            "handlers": ["default"],
            "level": "WARNING",
            "propagate": False,
        },

        "pygnmi": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },

        # 3. Loggers de Uvicorn para ver las solicitudes entrantes.
        "uvicorn.error": {
            "level": "INFO",
        },
        "uvicorn.access": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },

        # 4. Logger raíz: captura todo lo demás y lo establece en WARNING.
        "": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

def setup_logging():
    """Aplica la configuración de logging."""
    dictConfig(LOGGING_CONFIG)