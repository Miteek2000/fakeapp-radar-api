FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

# Usuario sin privilegios: el servicio nunca corre como root.
RUN useradd --create-home --uid 1000 app

WORKDIR /srv

# Solo dependencias de ejecucion (las de desarrollo quedan en requirements.txt).
COPY requirements-docker.txt .
RUN pip install -r requirements-docker.txt

COPY app ./app

# Carpeta compartida donde la API guarda los APK y el worker los lee.
RUN mkdir -p /data/uploads && chown app:app /data/uploads

USER app
EXPOSE 8000