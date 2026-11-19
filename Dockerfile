# Full node: the pouw-node, pouw and pouw-light-node binaries on slim Debian, run by
# pouw-deploy as node-1..3. The light node runs from the same image without
# POUW_DATA_DIR, which it rejects as an unknown variable:
#   --entrypoint env ... -u POUW_DATA_DIR pouw-light-node  (POUW_LIGHT_DATA_DIR=/data)
# curl is there for the compose healthcheck. The node keeps its key and data in /data.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
# RocksDB is compiled from source: it needs a C++ compiler and libclang for its bindings
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
# The cache mounts keep crates and target/ between local builds, the binaries are
# copied out because target/ is not part of the image
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p pouw-node -p pouw-cli -p pouw-light-node \
    && cp target/release/pouw-node target/release/pouw target/release/pouw-light-node /usr/local/bin/

FROM debian:bookworm-slim
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --no-create-home pouw \
    && install -d -o pouw -g pouw /data
COPY --from=build /usr/local/bin/pouw-node /usr/local/bin/pouw /usr/local/bin/pouw-light-node /usr/local/bin/
ENV POUW_DATA_DIR=/data
USER 10001
WORKDIR /data
# REST API and /health, metrics, P2P
EXPOSE 8000 9100 30333
ENTRYPOINT ["pouw-node"]
