# A workstation-client image: it generates a continuous, low-rate stream of
# NORMAL traffic against the flock's NPCs (browse, DB queries, cache ops, ...).
# All the CLI clients it drives are baked in at build time -- it never reaches
# the internet at runtime (flock networks are lab-internal). driver.py is pure
# stdlib and shells out to these, matching the pipeline's stdlib ethos.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        postgresql-client \
        default-mysql-client \
        redis-tools \
        ldap-utils \
        dnsutils \
        swaks \
        git \
        ftp \
        smbclient \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY driver.py /app/driver.py
COPY behaviors /app/behaviors

# The manifest is bind-mounted read-only at /manifest.json by npcctl; the
# container's own hostname is passed as CLIENT_HOSTNAME so it finds its entry.
CMD ["python", "driver.py"]
