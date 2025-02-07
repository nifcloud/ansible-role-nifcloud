FROM 31z4/tox

USER root

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        python3.6 \
        python3.7 \
        python3.8 \
        python3.9 \
        python3.10; \
    rm -rf /var/lib/apt/lists/*

USER tox
