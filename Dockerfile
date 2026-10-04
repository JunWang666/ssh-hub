FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/ssh-hub ./cmd/ssh-hub

FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/JunWang666/ssh-hub"
RUN addgroup -S -g 10001 sshhub \
    && adduser -S -D -H -u 10001 -G sshhub sshhub \
    && mkdir -p /data \
    && chmod 700 /data \
    && chown sshhub:sshhub /data
COPY --from=build /out/ssh-hub /usr/local/bin/ssh-hub
USER 10001:10001
ENV SSHHUB_DATA_DIR=/data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/ssh-hub"]
