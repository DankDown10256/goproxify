# =============================================================================
# GOPROXIFY — Dockerfile Agent (multi-stage)
# Construit le binaire unique et démarre en mode "agent"
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
# Utilise alpine (pas scratch) pour accéder au socket Docker Unix et /proc
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /goproxify /goproxify
# Config par défaut (valeurs surchargées par les GPX_* env vars en production)
COPY services/agent/config.json /internal/agent/config.json

# Métriques Prometheus
EXPOSE 9191

ENTRYPOINT ["/goproxify", "agent"]
