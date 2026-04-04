# syntax=docker/dockerfile:1.7

FROM rust:latest AS chef

RUN apt-get update \
    && apt-get install -y --no-install-recommends lld ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /app
ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --bin haven-backend

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libvips-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN useradd -m -u 10001 appuser \
    && mkdir -p /app/storage/avatars \
    && chown -R appuser:appuser /app

COPY --from=builder /app/target/release/haven-backend /usr/local/bin/haven-backend

USER appuser

EXPOSE 8086
CMD ["haven-backend"]
