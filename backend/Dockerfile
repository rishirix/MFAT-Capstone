FROM python:3.11-slim

# Install Docker CLI so the backend can run Volatility containers
RUN apt-get update && apt-get install -y \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy full project into container
COPY . .

# Create folders
RUN mkdir -p /app/dump /app/results

EXPOSE 5000

CMD ["python", "backend/app.py"]
