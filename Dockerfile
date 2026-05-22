# syntax=docker/dockerfile:1.6
#
# Reproduce artefacts/defmon-static.bin from the upstream .d64 in one shot.
#
# Usage:
#   docker build --target export --output artefacts .
#       -> writes ./artefacts/defmon-static.bin on the host
#
# Stages:
#   1. exomizer-build  builds exomizer 3.1.2 from the bitbucket tarball
#   2. fetcher         downloads defmon-20201008.zip, extracts the PRG from
#                      the .d64, runs `exomizer desfx`, flattens to a 64K bin
#   3. export          scratch image with just defmon-static.bin so
#                      `--output` writes only that one file to the host

FROM debian:bookworm-slim AS exomizer-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
RUN curl -fsSL https://bitbucket.org/magli143/exomizer/get/3.1.2.tar.gz \
        | tar xz \
    && mv magli143-exomizer-* exomizer \
    && make -s -C exomizer/src

FROM debian:bookworm-slim AS fetcher
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=exomizer-build /opt/exomizer/src/exomizer /usr/local/bin/exomizer
WORKDIR /work
COPY tools/__init__.py tools/__init__.py
COPY tools/d64.py tools/d64.py
COPY tools/fetch_static.py tools/fetch_static.py
RUN python3 -m tools.fetch_static \
    && test -f artefacts/defmon-static.bin

FROM scratch AS export
COPY --from=fetcher /work/artefacts/defmon-static.bin /defmon-static.bin
