# Smart Energy Monitor - containerised deployment
# Runs on Hugging Face Spaces (Docker SDK) and locally via docker-compose.
# HF Spaces run the container as UID 1000, so a dedicated user is created and
# the SQLite database lives in a writable /data directory (a persistent
# Storage Bucket can be attached to /data on HF for durability across restarts).
FROM python:3.11-slim

RUN useradd -m -u 1000 user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=user app.py .
COPY --chown=user templates ./templates

# Writable data directory for the SQLite database
RUN mkdir -p /data && chmod 777 /data

# Runtime configuration (can be overridden via docker-compose / environment)
ENV ENERGY_DB_PATH=/data/energy.db \
    HOST=0.0.0.0 \
    PORT=5000 \
    SECRET_KEY=change-me-in-production \
    SIM_INTERVAL=3 \
    RETENTION_DAYS=30

USER user

EXPOSE 5000

CMD ["python", "app.py"]
