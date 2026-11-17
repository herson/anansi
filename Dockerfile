FROM python:3.12-slim

# nmap is required for scanning
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure runtime directories exist
RUN mkdir -p logs reports data web/templates/static

# Listen on all interfaces so the published port works; start_server()
# refuses to do this unless ANANSI_API_KEY is set.
ENV ANANSI_HOST=0.0.0.0 \
    ANANSI_DB_PATH=/app/data/anansi.db

EXPOSE 8000

CMD ["python", "main.py", "--web"]
