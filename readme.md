
-----

# BNG Subscriber Management API

Una API REST de alto rendimiento construida con FastAPI para la gestión (CRUD) de suscriptores en un Broadband Network Gateway (BNG) a través del protocolo gNMI.

## Overview

Este proyecto proporciona una interfaz moderna y escalable para interactuar con dispositivos de red que soportan el modelo de datos YANG para la gestión de suscriptores. La API está diseñada para ser eficiente, manejando miles de suscriptores mediante estrategias de consulta optimizadas y está lista para ser desplegada en un entorno de producción utilizando contenedores Docker.

-----

## Features ✨

  * **Operaciones CRUD Completas:** Soporte para crear, leer, actualizar y eliminar suscriptores.
  * **Comunicación gNMI:** Utiliza el protocolo `gNMI` para una interacción moderna y model-driven con los dispositivos de red.
  * **Alto Rendimiento:** Implementa una arquitectura con Gunicorn y workers Uvicorn para aprovechar múltiples núcleos de CPU y manejar una alta concurrencia.
  * **Consultas Optimizadas:** Utiliza una estrategia de dos pasos (obtener llaves y luego detalles) para la consulta de listas, garantizando un rendimiento excelente incluso con miles de suscriptores.
  * **Validación de Datos:** Aprovecha Pydantic para la validación robusta de los datos de entrada y salida.
  * **Lógica de Reintentos:** Implementa persistencia en las operaciones de escritura para manejar bloqueos temporales de configuración en el dispositivo.
  * **Documentación Automática:** Genera automáticamente una interfaz de usuario interactiva (Swagger UI) para la documentación y prueba de la API.
  * **Lista para Contenedores:** Incluye un `Dockerfile` multi-etapa para crear imágenes Docker seguras, ligeras y optimizadas para producción.

-----

## Project Structure

```
.
├── app/
│   ├── __init__.py         # Inicializador del paquete
│   ├── logic.py            # Contiene toda la lógica de negocio y comunicación gNMI
│   ├── main.py             # Punto de entrada de la aplicación FastAPI
│   ├── models.py           # Definiciones de los modelos de datos (Pydantic)
│   └── routers/
│       ├── __init__.py
│       └── subscribers.py  # Definición de los endpoints de la API
├── Dockerfile              # Instrucciones para construir la imagen de producción
└── requirements.txt        # Dependencias del proyecto
```

-----

## Getting Started

### Prerequisites

  * Python 3.12+
  * Docker
  * Acceso a un dispositivo BNG con el servicio gNMI habilitado.

### Development Setup

1.  **Clonar el repositorio:**

    ```bash
    git clone <your-repo-url>
    cd <repo-name>
    ```

2.  **Crear y activar un entorno virtual:**

    ```bash
    # Para macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

    # Para Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Instalar dependencias:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configurar la conexión al dispositivo:**
    Abre el archivo `app/logic.py` y modifica el diccionario `DEVICES` con la IP, puerto y credenciales de tu BNG.

### Running the Application (Development)

Para iniciar el servidor de desarrollo con recarga automática:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

La API estará disponible en `http://localhost:5000`.

-----

## API Documentation

Este proyecto utiliza la funcionalidad de OpenAPI de FastAPI para generar documentación interactiva. Una vez que el servidor esté en ejecución, puedes acceder a la interfaz de Swagger UI en:

**`http://localhost:5000/docs`**

Desde esta interfaz, puedes ver todos los endpoints, sus parámetros, los modelos de respuesta y probar cada operación directamente desde tu navegador.

### Available Endpoints

  * `GET /simple/{bng}`: Obtiene una lista paginada de todos los suscriptores.
  * `POST /simple/{bng}`: Crea un nuevo suscriptor.
  * `GET /simple/{bng}/{accountidbss}`: Obtiene los detalles de un suscriptor específico.
  * `DELETE /simple/{bng}/{accountidbss}/{subnatid}`: Elimina un suscriptor (con validación de datos).
  * `PATCH /simple/{bng}/{accountidbss}/{subnatid}`: Actualiza parcialmente un suscriptor existente.

-----

## Deployment (Production)

La aplicación está diseñada para ser desplegada como un contenedor Docker utilizando Gunicorn como gestor de procesos y Uvicorn como el servidor ASGI.

### Build the Docker Image

Desde la raíz del proyecto, ejecuta el siguiente comando:

```bash
docker build -t mi-api-bng .
```

### Run the Container

Para iniciar el contenedor en segundo plano, mapeando el puerto 5000:

```bash
docker run -d --name api-bng -p 5000:5000 mi-api-bng
```

**Nota de Seguridad:** Para un despliegue en producción real, las credenciales del dispositivo no deben estar hardcodeadas en `app/logic.py`. Se recomienda gestionarlas de forma segura a través de **variables de entorno** o un sistema de gestión de secretos.