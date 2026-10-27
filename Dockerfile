FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistent storage volume for SQLite DB
VOLUME /app/data

EXPOSE 8088

ENV PORT=8088
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
