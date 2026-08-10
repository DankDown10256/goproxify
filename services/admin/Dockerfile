# =============================================================================
# GOPROXIFY — Dockerfile Administration (multi-stage)
# Stage 1 : Build backend (Go) — l'UI est embarquée via go:embed (internal/admin/ui/src)
# Stage 2 : Image finale minimale
# =============================================================================

# Stage 1 : Backend Go
FROM golang:1.25-alpine AS backend-builder

ARG VERSION_ADMIN=dev
ARG VERSION_CORE=dev
ARG VERSION_AGENT=dev
ARG VERSION_WEBAPP=dev
ARG VERSION_LANDING=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

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

# Stage 2 : Image finale (alpine pour wget healthcheck + ca-certificates)
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget tzdata

COPY --from=backend-builder /goproxify /goproxify
# Config par défaut de production (valeurs surchargées par les GPX_* env vars)
COPY services/admin/config.json /internal/admin/config.json

EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:9443/api/v1/health || exit 1

ENTRYPOINT ["/goproxify", "admin"]
