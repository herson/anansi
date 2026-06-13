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
RUN mkdir -p logs reports web/templates/static

EXPOSE 8000

CMD ["python", "main.py", "--web"]
