FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=0.3.0
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/luminariadev/raksa-pipeguard/internal/schema.Version=${VERSION}" \
    -o /out/raksa-pipeguard ./cmd/raksa-pipeguard

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /workspace
COPY --from=builder /out/raksa-pipeguard /usr/local/bin/raksa-pipeguard
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/raksa-pipeguard"]
CMD ["--help"]
