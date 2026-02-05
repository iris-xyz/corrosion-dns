# Build stage
FROM rust:bookworm as builder

RUN apt-get update && apt-get install -y build-essential gcc-x86-64-linux-gnu clang llvm

# Install mold linker
ENV MOLD_VERSION=1.11.0
RUN set -eux; \
    curl --fail --location "https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-x86_64-linux.tar.gz" --output /tmp/mold.tar.gz; \
    tar --directory "/usr/local" -xzvf "/tmp/mold.tar.gz" --strip-components 1; \
    rm /tmp/mold.tar.gz; \
    mold --version;

WORKDIR /usr/src/app
COPY . .

# Build corrosion-dns with prometheus and otel features
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:bookworm,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build --release -p corrosion-dns --features "prometheus,otel" && \
    mv target/release/corrosion-dns ./

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/corrosion-dns /usr/local/bin/

# Create non-root user
RUN useradd -ms /bin/bash corrosion
USER corrosion

EXPOSE 5353/udp
EXPOSE 5353/tcp
EXPOSE 9090/tcp

ENTRYPOINT ["corrosion-dns"]
CMD ["--config", "/etc/corrosion-dns/config.toml"]
