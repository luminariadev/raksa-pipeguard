FROM golang:1.24.2-alpine3.21 AS builder
WORKDIR /src
COPY . .

FROM alpine:3.21.3
RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=builder /src /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/server"]
