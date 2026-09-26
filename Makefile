# =============================================================================
# GOPROXIFY — Makefile
# =============================================================================

# Versions lues depuis versions.json
VERSION_ADMIN   := $(shell python3 -c "import json; print(json.load(open('versions.json'))['admin'])")
VERSION_EDGE    := $(shell python3 -c "import json; print(json.load(open('versions.json'))['edge'])")
VERSION_AGENT   := $(shell python3 -c "import json; print(json.load(open('versions.json'))['agent'])")
VERSION_WEBAPP  := $(shell python3 -c "import json; print(json.load(open('versions.json'))['webapp'])")
VERSION_LANDING := $(shell python3 -c "import json; print(json.load(open('versions.json'))['landing'])")

GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X 'main.VersionAdmin=$(VERSION_ADMIN)' \
	-X 'main.VersionEdge=$(VERSION_EDGE)' \
	-X 'main.VersionAgent=$(VERSION_AGENT)' \
	-X 'main.VersionWebapp=$(VERSION_WEBAPP)' \
	-X 'main.VersionLanding=$(VERSION_LANDING)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.BuildTime=$(BUILD_TIME)'

DOCKER_ARGS := \
	--build-arg VERSION_ADMIN=$(VERSION_ADMIN) \
	--build-arg VERSION_EDGE=$(VERSION_EDGE) \
	--build-arg VERSION_AGENT=$(VERSION_AGENT) \
	--build-arg VERSION_WEBAPP=$(VERSION_WEBAPP) \
	--build-arg VERSION_LANDING=$(VERSION_LANDING) \
	--build-arg GIT_COMMIT=$(GIT_COMMIT) \
	--build-arg BUILD_TIME=$(BUILD_TIME)

# Défaut = GHCR public. Registry labo : make push-all REGISTRY=…
REGISTRY := ghcr.io/vincamok/goproxify

.PHONY: all build build-dev up up-build down restart \
        docker-admin docker-edge docker-agent docker-landing docker-all \
        push-admin push-edge push-agent push-landing push-all \
        test test-prebuild lint clean version sync-versions

# -----------------------------------------------------------------------------
# Stack Docker Compose
# -----------------------------------------------------------------------------

# Build local + démarrage (contourne le registry, pour le développement)
up-build:
	docker build $(DOCKER_ARGS) -t $(REGISTRY)/admin:latest -f services/admin/Dockerfile .
	docker build $(DOCKER_ARGS) -t $(REGISTRY)/edge:latest  -f services/edge/Dockerfile  .
	docker build $(DOCKER_ARGS) -t $(REGISTRY)/agent:latest -f services/agent/Dockerfile .
	docker compose up -d

# Démarre la stack (images déjà présentes localement ou dans le registry)
up:
	docker compose up -d

# Arrête la stack
down:
	docker compose down

# Tire les dernières images du registry et redémarre
pull-up:
	docker compose pull
	docker compose up -d

# -----------------------------------------------------------------------------
# Binaire local
# -----------------------------------------------------------------------------

all: build

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o goproxify ./cmd/goproxify

build-dev:
	go build -ldflags="$(LDFLAGS)" -o goproxify ./cmd/goproxify

version:
	@echo "admin    $(VERSION_ADMIN)"
	@echo "edge     $(VERSION_EDGE)"
	@echo "agent    $(VERSION_AGENT)"
	@echo "webapp   $(VERSION_WEBAPP)"
	@echo "landing  $(VERSION_LANDING)"
	@echo "commit   $(GIT_COMMIT)"
	@echo "built    $(BUILD_TIME)"

sync-versions:
	@./ci/sync-versions.sh

# -----------------------------------------------------------------------------
# Images Docker
# -----------------------------------------------------------------------------

docker-admin:
	docker build $(DOCKER_ARGS) \
		-t $(REGISTRY)/admin:$(VERSION_ADMIN) \
		-t $(REGISTRY)/admin:latest \
		-f services/admin/Dockerfile .

docker-edge:
	docker build $(DOCKER_ARGS) \
		-t $(REGISTRY)/edge:$(VERSION_EDGE) \
		-t $(REGISTRY)/edge:latest \
		-f services/edge/Dockerfile .

docker-agent:
	docker build $(DOCKER_ARGS) \
		-t $(REGISTRY)/agent:$(VERSION_AGENT) \
		-t $(REGISTRY)/agent:latest \
		-f services/agent/Dockerfile .

docker-landing:
	docker build \
		--build-arg VERSION_LANDING=$(VERSION_LANDING) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(REGISTRY)/landing:$(VERSION_LANDING) \
		-t $(REGISTRY)/landing:latest \
		-f services/landing/Dockerfile services/landing

docker-all: docker-admin docker-edge docker-agent docker-landing

# -----------------------------------------------------------------------------
# Push vers le registry
# -----------------------------------------------------------------------------

push-admin: docker-admin
	docker push $(REGISTRY)/admin:$(VERSION_ADMIN)
	docker push $(REGISTRY)/admin:latest

push-edge: docker-edge
	docker push $(REGISTRY)/edge:$(VERSION_EDGE)
	docker push $(REGISTRY)/edge:latest

push-agent: docker-agent
	docker push $(REGISTRY)/agent:$(VERSION_AGENT)
	docker push $(REGISTRY)/agent:latest

push-landing: docker-landing
	docker push $(REGISTRY)/landing:$(VERSION_LANDING)
	docker push $(REGISTRY)/landing:latest

push-all: push-admin push-edge push-agent push-landing

# -----------------------------------------------------------------------------
# Qualité
# -----------------------------------------------------------------------------

test:
	go test ./...

# Tests de non-régression revue (P0/P1) — à faire passer AVANT docker-*/push-*.
# Inclut -race pour Shadow (#9). Échec attendu tant que les correctifs ne sont pas mergés.
test-prebuild:
	@echo "==> test-prebuild (revue P0/P1)"
	@mkdir -p .gotmp/tmp .gotmp/cache
	TMPDIR="$(CURDIR)/.gotmp/tmp" GOCACHE="$(CURDIR)/.gotmp/cache" \
	CGO_ENABLED=1 go test -count=1 -timeout 5m -race \
		./internal/edge/middleware/ \
		./internal/edge/router/ \
		./internal/edge/proxy/ \
		./internal/edge/ws/ \
		-run 'TestReviewP0_|TestReviewP1_|TestReviewP2_|TestVerifyOIDCIDToken|TestTableReplace|TestValidateAdmin'
	@echo "==> SUCCESS test-prebuild"

lint:
	golangci-lint run ./...

# -----------------------------------------------------------------------------
# Nettoyage
# -----------------------------------------------------------------------------

clean:
	rm -f goproxify
	docker rmi $(REGISTRY)/admin:$(VERSION_ADMIN) \
	           $(REGISTRY)/edge:$(VERSION_EDGE) \
	           $(REGISTRY)/agent:$(VERSION_AGENT) \
	           $(REGISTRY)/landing:$(VERSION_LANDING) 2>/dev/null || true
