FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY scripts/ /scripts/
CMD ["python3", "/scripts/generate-sample-data.py", "--events", "200", "--send-hec"]
