# fakeapp-radar-api

API de FakeApp Radar (FastAPI). Analiza APKs de forma estática, sin ejecutarlos.

## Correr en desarrollo
1. `python -m venv .venv` y activar con `.\.venv\Scripts\Activate.ps1`
2. `pip install -r requirements.txt`
3. Copiar `.env.example` a `.env`
4. `uvicorn app.main:app --reload`
5. Documentación interactiva en http://127.0.0.1:8000/docs

## Pruebas
`python -m pytest -q`