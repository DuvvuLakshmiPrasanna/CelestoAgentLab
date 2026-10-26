# Trusted control plane: the run-ledger API.
# Firecracker / Celesto guests are NOT started here; they are created through the
# Celesto SDK (see agent/providers/celesto_provider.py) when a job needs a computer.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl is used by the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-celesto.txt ./
RUN pip install -r requirements.txt

# The Celesto SDK is installed in its own, failure-tolerant layer: if a wheel is not
# available for this platform the API still starts, serves /health, /api/runs and the
# shipped reports, and POST /api/jobs reports "celesto SDK not installed".
RUN pip install -r requirements-celesto.txt \
    || echo "WARNING: celesto SDK not installable here; guest-creating jobs are disabled"

COPY app ./app
COPY agent ./agent
COPY seeds ./seeds
COPY reports ./reports
COPY logs ./logs
COPY README.md ./README.md

RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8080
CMD ["python", "-m", "app"]
