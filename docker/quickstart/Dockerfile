# docker/quickstart/Dockerfile
FROM python:3.11-slim

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pydantic

WORKDIR /app

# Copy both quickstart scripts into image
COPY mcs-examples/quickstart/fastapi_server_mcs_quickstart.py .
COPY mcs-examples/quickstart/fastapi_rest_quickstart.py .

# default port (wird ggf. vom Service überschrieben)
# EXPOSE 8000
