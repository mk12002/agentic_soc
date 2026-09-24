# SOC platform image. Core platform by default; add the phishing ML stack with
#   docker build --build-arg WITH_PHISHING_ENGINE=true -f deploy/Dockerfile .
FROM python:3.11-slim AS builder
ARG WITH_PHISHING_ENGINE=false
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev libzbar0 git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements/ requirements/
RUN pip install --no-cache-dir --prefix=/install -r requirements/platform.txt \
 && if [ "$WITH_PHISHING_ENGINE" = "true" ]; then \
      pip install --no-cache-dir --prefix=/install torch --index-url https://download.pytorch.org/whl/cpu && \
      pip install --no-cache-dir --prefix=/install -r requirements/phishing.txt ; \
    else pip install --no-cache-dir --prefix=/install pyzbar Pillow ppdeep ; fi

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 libgomp1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 soc && useradd --uid 1001 --gid soc --create-home soc
COPY --from=builder /install /usr/local
WORKDIR /app
COPY pyproject.toml README.md ./
COPY soc_platform/ soc_platform/
COPY config/ config/
COPY scripts/ scripts/
COPY artifacts/ artifacts/
RUN pip install --no-cache-dir --no-deps -e . && mkdir -p /app/data && chown -R soc:soc /app
USER soc
ENV SOC_CONNECTORS_CONFIG=/app/config/connectors.yaml SOC_RAW_PAYLOAD_DIR=/app/data/raw \
    SOC_REPORT_OUTPUT_DIR=/app/data/reports SOC_PHISHING_HOME=/app/artifacts/phishing PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 CMD curl -fs http://localhost:8080/health || exit 1
CMD ["uvicorn", "soc_platform.api.app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
