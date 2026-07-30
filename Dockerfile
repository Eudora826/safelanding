# Dockerfile - one-command package for the merged SafeLanding app.
#   docker build -t safelanding .
#   docker run -p 8000:8000 safelanding
# Then open http://localhost:8000  (and http://localhost:8000/admin)
#
# The SQLite database is created at /app/data/safelanding.db on first start,
# seeded from the JSON files. Mount a volume on /app/data to persist reports
# across container restarts:
#   docker run -p 8000:8000 -v safelanding_data:/app/data safelanding

FROM python:3.12-slim
WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY static ./static
COPY data ./data

WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
