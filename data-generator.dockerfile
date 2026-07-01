FROM python:3.11-slim

LABEL maintainer="Cipher7788"
LABEL description="SOC Detection Lab – Data Generator Container"

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir faker requests

# Copy scripts
COPY scripts/ /scripts/
COPY data-sources/ /data-sources/

# Make scripts executable
RUN chmod +x /scripts/generate-sample-data.py

# Default: generate 200 mixed events and forward to Splunk HEC
CMD ["python3", "/scripts/generate-sample-data.py", \
     "--events", "200", \
     "--output", "/data-sources/logs/generated-events.json"]
