FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CCS_PUBLIC_KEY_PATH=/app/keys/ed25519.pub \
    CCS_MAX_BODY_BYTES=262144

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
 && useradd --system --uid 10002 --create-home --home-dir /home/aivfpublic aivfpublic
COPY app /app/app
RUN chown -R aivfpublic:aivfpublic /app
USER aivfpublic
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips=127.0.0.1"]
