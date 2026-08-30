FROM python:3.13-slim

WORKDIR /app
COPY app.py /app/app.py

RUN useradd --system --uid 10002 --no-create-home --shell /usr/sbin/nologin aivf-wwknow-demo

USER aivf-wwknow-demo
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEMO_HOST=127.0.0.1 \
    DEMO_PORT=18051 \
    CCS_HOST=127.0.0.1 \
    CCS_PORT=50051 \
    PUBLIC_VERIFIER_URL=http://127.0.0.1:18050/api/verify

CMD ["python", "/app/app.py"]
