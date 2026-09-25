# =============================================================================
# GOPROXIFY — Dockerfile Core (multi-stage)
# Construit le binaire unique et démarre en mode "core"
# =============================================================================

# Stage 1 : Build
FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

ARG VERSION_ADMIN=dev
ARG VERSION_CORE=dev
ARG VERSION_AGENT=dev
ARG VERSION_WEBAPP=dev
ARG VERSION_LANDING=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w \
      -X 'main.VersionAdmin=${VERSION_ADMIN}' \
      -X 'main.VersionCore=${VERSION_CORE}' \
      -X 'main.VersionAgent=${VERSION_AGENT}' \
      -X 'main.VersionWebapp=${VERSION_WEBAPP}' \
      -X 'main.VersionLanding=${VERSION_LANDING}' \
      -X 'main.GitCommit=${GIT_COMMIT}' \
      -X 'main.BuildTime=${BUILD_TIME}'" \
    -o /goproxify ./cmd/goproxify

# Stage 2 : Image minimale
FROM scratch

COPY --from=builder /goproxify /goproxify
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Pas de config.json embarqué : core.json est généré au premier démarrage
# sous /etc/goproxify (volume persistant) à partir des variables GPX_*,
# voir internal/config/bootstrap.go.

# HTTP, HTTPS (TCP + UDP/QUIC), API interne
EXPOSE 80 443 443/udp 8000

ENTRYPOINT ["/goproxify", "core"]
