FROM python:3.13-slim
WORKDIR /app
COPY aivf-ccs-verifier /app/aivf-ccs-verifier
RUN pip install --no-cache-dir /app/aivf-ccs-verifier

RUN useradd --system --uid 10001 --create-home --home-dir /var/lib/aivf-ccs aivfccs \
 && mkdir -p /var/lib/aivf-ccs/keys /run/aivf-ccs \
 && chown -R aivfccs:aivfccs /var/lib/aivf-ccs /run/aivf-ccs

USER aivfccs
ENV CCS_TRANSPORT=tcp \
    CCS_HOST=0.0.0.0 \
    CCS_PORT=50051 \
    CCS_HEALTH_HOST=0.0.0.0 \
    CCS_HEALTH_PORT=8080 \
    CCS_DB=/var/lib/aivf-ccs/evidence.db \
    CCS_KEY_FILE=/var/lib/aivf-ccs/keys/ed25519.seed \
    CCS_ISSUER=urn:wwknow:aivf:verifier:prod \
    CCS_AUDIENCE=urn:wwknow:aivf:executor:prod \
    CCS_KEY_ID=aivf-ed25519-1
EXPOSE 50051 8080
CMD ["aivf-ccs-verifier"]
