# Build stage - build a fully static binary
FROM rust:1.88-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY src ./src

# Build release binary (statically linked with musl)
RUN touch src/main.rs && cargo build --release

# Runtime stage - use scratch or minimal image
# Since the binary is statically linked with musl, we can use a minimal base
FROM scratch

WORKDIR /app

# Copy the static binary
COPY --from=builder /app/target/release/honmoon-server /honmoon-server

# Copy CA certificates from builder for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Stamped by `make deploy-build` so /health can report which commit is
# actually running. Cargo.toml's version has been 0.1.0 since the file was
# created, so it never told us anything.
ARG HONMOON_BUILD=unknown
ENV HONMOON_BUILD=$HONMOON_BUILD

ENV BIND_ADDR=0.0.0.0:8080
ENV RUST_LOG=honmoon_server=info,tower_http=info

EXPOSE 8080

# No health check (curl not available in scratch)
# Docker compose can use depends_on with service_started instead

CMD ["/honmoon-server"]
