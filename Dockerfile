FROM python:3.12-slim

LABEL maintainer="Frostveil Contributors"
LABEL description="Frostveil — Advanced browser forensics & penetration testing toolkit"
LABEL version="2.1.0"

# Security: run as non-root
RUN groupadd -r frostveil && useradd -r -g frostveil -m frostveil

WORKDIR /opt/frostveil

# Copy source
COPY modules/ modules/
COPY ui/ ui/
COPY plugins/ plugins/
COPY main.py server.py pyproject.toml README.md LICENSE ./
COPY tests/ tests/

# No dependencies to install — pure Python

# Create output directory
RUN mkdir -p /output && chown frostveil:frostveil /output

USER frostveil

# Default: show help
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# Usage examples:
#   docker build -t frostveil .
#   docker run -v /path/to/browser/data:/data -v $(pwd)/output:/output frostveil --full --format json --out /output/evidence.json
#   docker run -p 8080:8080 frostveil --dashboard --bind 0.0.0.0
