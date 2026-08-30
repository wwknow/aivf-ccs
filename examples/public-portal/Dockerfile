FROM python:3.13-slim

WORKDIR /app
COPY app.py /app/app.py

RUN useradd --system --uid 10003 --no-create-home --shell /usr/sbin/nologin aivfportal

USER aivfportal
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORTAL_HOST=127.0.0.1 \
    PORTAL_PORT=18052 \
    VERIFIER_BASE=http://127.0.0.1:18050 \
    DEMO_BASE=http://127.0.0.1:18051

CMD ["python", "/app/app.py"]
