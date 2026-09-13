FROM python:3.12-slim AS base

# Non-root from the start. Adding a USER line at the end of a Dockerfile that
# pip-installed as root leaves root-owned files the app cannot write.
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app

WORKDIR /app

# Dependencies in their own layer so a source change does not reinstall them.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

# PYTHONUNBUFFERED is not optional here. Without it Python block-buffers stdout
# when it is a pipe rather than a terminal, so logs arrive at the collector in
# 4KB chunks, minutes late and batched. Every log line this platform collects
# depends on it.

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/healthz',timeout=2).status==200 else 1)"

# gunicorn, not the Flask dev server. The dev server is single-threaded and
# explicitly documented as unsuitable for anything but development.
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "2", \
     "--threads", "4", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "app.main:app"]
