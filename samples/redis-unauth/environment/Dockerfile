FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      file binutils grep ripgrep jq python3 python3-pip less tree \
      gzip xxd poppler-utils ca-certificates \
      tmux asciinema \
    && rm -rf /var/lib/apt/lists/*
# binutils -> strings/strings -e l (binary blobs, registry hives, .evtx); gzip -> zcat rotated
# logs; xxd -> hexdump; poppler-utils -> pdftotext (CTI PDFs); ca-certificates -> judge HTTPS.
# tmux + asciinema -> baked so the terminus recording harness finds them already present and
# SKIPS its in-container `apt-get install` at agent setup. That install hits the network every
# run (apt lists are purged above); when it is slow it trips harbor's 120s exec ceiling, which
# surfaces as a RuntimeError past terminus's best-effort guard and fails the whole trial.

# Read-only forensic image at /disk (extracted INTO /disk, not /), security-product feed at /sas.
COPY disk.tar.gz /tmp/
COPY disk.tar.gz.sha256 /tmp/
RUN cd /tmp && sha256sum -c disk.tar.gz.sha256 \
 && mkdir -p /disk && tar -xzf disk.tar.gz -C /disk \
 && chmod -R a-w /disk && rm /tmp/disk.tar.gz*

COPY sas-mock /sas
RUN chmod -R a-w /sas
WORKDIR /app
