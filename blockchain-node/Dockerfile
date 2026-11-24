FROM python:3.12-slim

RUN groupadd --gid 10002 chain && useradd --uid 10002 --gid chain --no-create-home chain

WORKDIR /app
COPY requirements.txt .
COPY wheels /wheels
RUN pip install --no-index --find-links=/wheels -r requirements.txt
COPY node/ ./node/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RPC_PORT=8545 \
    P2P_PORT=30303

# PYTHONUNBUFFERED is load-bearing, not hygiene: without it Python block-buffers
# stdout when it is a pipe, so consensus events reach the collector in 4KB
# chunks, minutes late. A slashing alert delayed by minutes is worthless.

USER chain
EXPOSE 8545 30303

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8545/healthz',timeout=2).status==200 else 1)"

# Run the module directly rather than under gunicorn. The node is not a
# stateless web app: it owns a consensus loop and in-memory chain state, so
# multiple worker processes would each run their own independent chain and
# then double-sign against each other -- which is precisely the failure this
# project detects, and not one worth shipping by accident.
CMD ["python", "-m", "node.main"]
