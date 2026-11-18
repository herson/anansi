FROM python:3.14-slim

# nmap is required for scanning
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin anansi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .

# Runtime directories are the only paths the app user can write; the code
# itself stays root-owned and read-only to it.
RUN mkdir -p logs reports data web/templates/static \
    && chown anansi:anansi logs reports data

# Unprivileged, so nmap uses TCP connect scans (-sT) rather than SYN scans (-sS).
USER anansi

# Listen on all interfaces so the published port works; start_server()
# refuses to do this unless ANANSI_API_KEY is set.
ENV ANANSI_HOST=0.0.0.0 \
    ANANSI_DB_PATH=/app/data/anansi.db

EXPOSE 8000

CMD ["python", "main.py", "--web"]
