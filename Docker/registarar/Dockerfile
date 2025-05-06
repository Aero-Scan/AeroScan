FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py .
# Make sure api.py runs on host 0.0.0.0 to be reachable
CMD ["python", "api.py"]

