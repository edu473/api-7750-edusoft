# --- Etapa 1: El Constructor (Builder) ---
# Usamos una imagen oficial de Python. La etiqueta 'slim' es más ligera.
FROM python:3.12-slim as builder

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# Creamos un entorno virtual para mantener las dependencias aisladas
RUN python -m venv /opt/venv
# Activamos el venv para los siguientes comandos RUN
ENV PATH="/opt/venv/bin:$PATH"

# Copiamos solo el archivo de requerimientos primero para aprovechar el caché de Docker
COPY app/requirements.txt .

# Instalamos las dependencias. El --no-cache-dir reduce el tamaño de la imagen
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Ahora copiamos el resto del código de la aplicación
COPY ./app /app/app


# --- Etapa 2: La Imagen Final (Final) ---
# Empezamos de nuevo desde la misma base para una imagen limpia
FROM python:3.12-slim

# Creamos un usuario no-root para ejecutar la aplicación por seguridad
RUN addgroup --system appgroup && adduser --system --group appuser

# Establecemos el directorio de trabajo
WORKDIR /app

# Copiamos el entorno virtual con las dependencias ya instaladas desde la etapa 'builder'
COPY --from=builder /opt/venv /opt/venv
# Copiamos el código de la aplicación desde la etapa 'builder'
COPY --from=builder /app/app /app/app

# Hacemos que el usuario 'appuser' sea el propietario de los archivos
RUN chown -R appuser:appgroup /app

# Activamos el entorno virtual para el comando final
ENV PATH="/opt/venv/bin:$PATH"

# Cambiamos al usuario no-root
USER appuser

# Exponemos el puerto en el que correrá Gunicorn
EXPOSE 7750

# El comando para ejecutar la aplicación en producción
# -w: número de workers. Un buen punto de partida es (2 * N_CORES_CPU) + 1
# -k: la clase de worker a usar (los workers de Uvicorn)
# -b: la dirección y puerto donde escuchar

CMD ["gunicorn", "-w", "8", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "-b", "0.0.0.0:7750"]