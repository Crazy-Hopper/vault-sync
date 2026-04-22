FROM rust:1.93.0 AS builder

# Increase stack size to prevent SIGSEGV in QEMU
ENV RUST_MIN_STACK=16777216

WORKDIR /usr/src/vault-sync
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/vault-sync /usr/local/bin/vault-sync
# Smoke check that the image has all required libraries
RUN /usr/local/bin/vault-sync --version
CMD ["vault-sync"]
