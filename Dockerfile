# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o netflowmap ./cmd/netflowmap

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 netflowmap

# Copy binary from builder
COPY --from=builder /build/netflowmap /app/netflowmap

# Copy web assets
COPY --from=builder /build/web /app/web

# Copy example configs
COPY --from=builder /build/configs /app/configs

# Create data directory for GeoIP database
RUN mkdir -p /app/data && chown -R netflowmap:netflowmap /app

# Switch to non-root user
USER netflowmap

# Expose ports
# 8080 - HTTP Web UI
# 2055 - NetFlow UDP
EXPOSE 8080
EXPOSE 2055/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/api/health || exit 1

# Run
ENTRYPOINT ["/app/netflowmap"]
CMD ["--config", "/app/config.yml"]







