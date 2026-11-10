FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py admin.py smoke_test.py ./
# The private key is provided at runtime (Render Secret File / env var) — never baked into the image.
ENV TROVE_DB=/data/activations.db
EXPOSE 10000
# Render passes $PORT; default to 10000 for local docker runs.
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --proxy-headers --forwarded-allow-ips='*'"]
