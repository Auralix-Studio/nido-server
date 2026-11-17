# Imagen de despliegue sin sudo para Nido.
ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /nido .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates docker-cli iproute2 iputils
COPY --from=build /nido /usr/local/bin/nido
COPY config.yaml.example /config.yaml.example
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
