# docker/quickstart/Dockerfile
FROM python:3.11-slim

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic

WORKDIR /app

# Kopiere beide Demo-Skripte ins Image
COPY mcs/examples/fastapi_server_mcs_quickstart.py .
COPY mcs/examples/fastapi_rest_quickstart.py .

# default port (wird ggf. vom Service überschrieben)
# EXPOSE 8000
