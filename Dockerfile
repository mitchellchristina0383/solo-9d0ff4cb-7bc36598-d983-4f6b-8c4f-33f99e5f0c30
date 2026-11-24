FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --create-home app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

ENV ADMISSION_DB_PATH=/data/admission.db \
    ADMISSION_VERIFY_DELAY_MS=500 \
    ADMISSION_HANDOVER_SOURCE_DIR=/volumes/source \
    ADMISSION_HANDOVER_TARGET_DIR=/volumes/handover

RUN mkdir -p /data /volumes/source /volumes/handover \
 && chown -R app:app /app /data /volumes
USER app

EXPOSE 8000
VOLUME ["/data", "/volumes/source", "/volumes/handover"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

CMD ["uvicorn", "app.web:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
