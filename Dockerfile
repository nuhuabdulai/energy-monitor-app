# Smart Energy Monitor - containerised deployment
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY templates ./templates

# Persist the SQLite database outside the container
VOLUME /app/data

# Runtime configuration (can be overridden via docker-compose / environment)
# ENERGY_DB_PATH must match the env var name read by app.py so the
# /app/data volume actually persists the database across restarts.
ENV ENERGY_DB_PATH=/app/data/energy.db \
    HOST=0.0.0.0 \
    SIM_INTERVAL=3 \
    RETENTION_DAYS=30

EXPOSE 5000

CMD ["python", "app.py"]
