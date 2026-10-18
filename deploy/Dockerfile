# SOC platform image. Core platform by default; add the phishing ML stack with
#   docker build --build-arg WITH_PHISHING_ENGINE=true -f deploy/Dockerfile .
FROM python:3.11-slim AS builder
ARG WITH_PHISHING_ENGINE=false
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev libzbar0 git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements/ requirements/
RUN pip install --no-cache-dir --prefix=/install -r requirements/platform.txt -c requirements/platform.lock \
 && if [ "$WITH_PHISHING_ENGINE" = "true" ]; then \
      pip install --no-cache-dir --prefix=/install -r requirements/phishing.txt ; \
    else pip install --no-cache-dir --prefix=/install pyzbar Pillow ppdeep ; fi

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 libgomp1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 soc && useradd --uid 1001 --gid soc --create-home soc
# the base image's own setuptools carries old vendored copies (wheel, jaraco.context) with known CVEs: upgrade it
# cleanly first (setuptools held to the locked version), so nothing stale survives the copy below
COPY requirements/platform.lock /tmp/platform.lock
RUN python -m pip install --no-cache-dir --upgrade setuptools -c /tmp/platform.lock && rm /tmp/platform.lock
COPY --from=builder /install /usr/local
WORKDIR /app
COPY pyproject.toml README.md ./
COPY soc_platform/ soc_platform/
COPY config/ config/
COPY scripts/ scripts/
COPY artifacts/ artifacts/
# pip is a build tool: removed from the runtime image (no package manager in production; its vendored libraries
# are not shipped)
RUN pip install --no-cache-dir --no-deps -e . && python -m pip uninstall -y pip \
    && mkdir -p /app/data && chown -R soc:soc /app
USER soc
ENV SOC_CONNECTORS_CONFIG=/app/config/connectors.yaml SOC_RAW_PAYLOAD_DIR=/app/data/raw \
    SOC_REPORT_OUTPUT_DIR=/app/data/reports SOC_PHISHING_HOME=/app/artifacts/phishing PYTHONUNBUFFERED=1     SOC_HOST=0.0.0.0 SOC_PORT=8080 SOC_API_WORKERS=4
EXPOSE 8080
# readiness: the process answers and its database does (/health/live is the liveness check, /health the full status)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 CMD curl -fs http://localhost:8080/health/ready || exit 1
# workers: one per CPU core given to the container (SOC_API_WORKERS); X-Forwarded-For is handled by the app
CMD ["python", "-m", "soc_platform", "serve"]
