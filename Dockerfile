# syntax=docker/dockerfile:1
# The relay image of UMBRA, and the test network of scripts/devnet.sh.
#
#   docker compose build                               # the relay image
#   docker compose -f compose.devnet.yaml up --build   # the test network
#
# deploy/relay/README.md gives the steps of a relay.
#
# The compiler is inside the trust boundary (Part 14 §14.5.1), thus a digest
# pins each image, and the toolchain is the one of rust-toolchain.toml. A new
# toolchain takes a new digest, as in scripts/build-linux.sh.

FROM rust:1.99.1-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29 AS build
WORKDIR /src
COPY . .
RUN grep -q '^channel = "1.99.1"$' rust-toolchain.toml || { \
        echo "rust-toolchain.toml names another toolchain. Pin its image in the Dockerfile." >&2; \
        exit 1; \
    }
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p umbra-relay --features native --bins \
    && cargo build --release --locked -p umbra-ffi --features runtime --bin umbra-authority \
    && mkdir -p /out \
    && for bin in umbra-relay umbra-ndr umbra-directory umbra-signer umbra-measurer \
        umbra-test-authority umbra-authority; do \
        install -m 0755 "target/release/$bin" "/out/$bin"; \
    done

# The relay on a small base, under a user with no privilege. curl fetches
# the first manifest.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS relay
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /umbra --shell /usr/sbin/nologin umbra
COPY --from=build /out/umbra-relay /usr/local/bin/umbra-relay
COPY deploy/relay/entry.sh /usr/local/bin/umbra-entry
# The public values of the network. The key set is the one that the release
# app pins.
COPY deploy/relay/network.env /usr/local/share/umbra/network.env
COPY android/app/src/release/assets/umbra-keyset.bin /usr/local/share/umbra/keyset.bin
# A checkout on Windows can give the script CRLF line ends.
RUN sed -i 's/\r$//' /usr/local/bin/umbra-entry /usr/local/share/umbra/network.env \
    && chmod 0755 /usr/local/bin/umbra-entry
USER umbra
WORKDIR /umbra
ENTRYPOINT ["umbra-entry"]

# The test network: seven relays, the NDR, the directory, the authority, and
# the measurer in one container. Its seeds are in the repository, thus it
# protects nothing.
FROM relay AS devnet
USER root
COPY --from=build /out/ /usr/local/bin/
# devnet.sh compares the keys of the network with the fixtures through python3.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/devnet.sh scripts/devnet.sh
COPY tests/fixtures tests/fixtures
# A checkout on Windows can give the text fixtures CRLF line ends.
RUN find tests/fixtures -type f \( -name '*.conf' -o -name '*.pem' -o -name '*.key' \) \
        -exec sed -i 's/\r$//' {} + \
    && mkdir -p target/devnet \
    && chown -R umbra:umbra target
USER umbra
ENV UMBRA_DEVNET_BIN=/usr/local/bin
EXPOSE 7441 7446
ENTRYPOINT ["bash", "scripts/devnet.sh"]
