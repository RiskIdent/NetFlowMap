# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Version is passed as build argument
ARG VERSION=dev

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary (static, stripped, with version injected)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o netflowmap ./cmd/netflowmap

# Runtime stage - Distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/netflowmap /app/netflowmap

# Copy web assets
COPY --from=builder /build/web /app/web

# Copy timezone data for proper time handling
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Expose ports
# 8080 - HTTP Web UI
# 2055 - NetFlow UDP
EXPOSE 8080
EXPOSE 2055/udp

# Health check using built-in healthcheck command
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/netflowmap", "--healthcheck"]

# Run as non-root (distroless:nonroot runs as uid 65532)
USER nonroot:nonroot

# Run
ENTRYPOINT ["/app/netflowmap"]
CMD ["--config", "/app/config.yml"]
