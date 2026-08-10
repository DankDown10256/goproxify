# =============================================================================
# GOPROXIFY — Makefile
# =============================================================================

# Versions lues depuis versions.json
VERSION_ADMIN   := $(shell python3 -c "import json; print(json.load(open('versions.json'))['admin'])")
VERSION_CORE    := $(shell python3 -c "import json; print(json.load(open('versions.json'))['core'])")
VERSION_AGENT   := $(shell python3 -c "import json; print(json.load(open('versions.json'))['agent'])")
VERSION_WEBAPP  := $(shell python3 -c "import json; print(json.load(open('versions.json'))['webapp'])")
VERSION_LANDING := $(shell python3 -c "import json; print(json.load(open('versions.json'))['landing'])")

GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X 'main.VersionAdmin=$(VERSION_ADMIN)' \
	-X 'main.VersionCore=$(VERSION_CORE)' \
	-X 'main.VersionAgent=$(VERSION_AGENT)' \
	-X 'main.VersionWebapp=$(VERSION_WEBAPP)' \
	-X 'main.VersionLanding=$(VERSION_LANDING)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.BuildTime=$(BUILD_TIME)'

DOCKER_ARGS := \
	--build-arg VERSION_ADMIN=$(VERSION_ADMIN) \
	--build-arg VERSION_CORE=$(VERSION_CORE) \
	--build-arg VERSION_AGENT=$(VERSION_AGENT) \
	--build-arg VERSION_WEBAPP=$(VERSION_WEBAPP) \
	--build-arg VERSION_LANDING=$(VERSION_LANDING) \
	--build-arg GIT_COMMIT=$(GIT_COMMIT) \
	--build-arg BUILD_TIME=$(BUILD_TIME)

# Défaut = registry Harness privé. Pour GHCR public :
#   make push-all REGISTRY=ghcr.io/vincamok/goproxify
REGISTRY := ghcr.io/vincamok/goproxify

.PHONY: all build build-dev up up-build down restart \
        docker-admin docker-core docker-agent docker-landing docker-all \
        push-admin push-core push-agent push-landing push-all \
        test test-prebuild lint clean version sync-versions prepublish-host

# -----------------------------------------------------------------------------
# Stack Docker Compose
# -----------------------------------------------------------------------------

# Build local + démarrage (contourne le registry, pour le développement)
up-build:
	docker build $(DOCKER_ARGS) -t $(REGISTRY)/admin:latest -f services/admin/Dockerfile .
	docker build $(DOCKER_ARGS) -t $(REGISTRY)/core:latest  -f services/core/Dockerfile  .
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
	@echo "core     $(VERSION_CORE)"
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

docker-core:
	docker build $(DOCKER_ARGS) \
		-t $(REGISTRY)/core:$(VERSION_CORE) \
		-t $(REGISTRY)/core:latest \
		-f services/core/Dockerfile .

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

docker-all: docker-admin docker-core docker-agent docker-landing

# -----------------------------------------------------------------------------
# Push vers le registry
# -----------------------------------------------------------------------------

push-admin: docker-admin
	docker push $(REGISTRY)/admin:$(VERSION_ADMIN)
	docker push $(REGISTRY)/admin:latest

push-core: docker-core
	docker push $(REGISTRY)/core:$(VERSION_CORE)
	docker push $(REGISTRY)/core:latest

push-agent: docker-agent
	docker push $(REGISTRY)/agent:$(VERSION_AGENT)
	docker push $(REGISTRY)/agent:latest

push-landing: docker-landing
	docker push $(REGISTRY)/landing:$(VERSION_LANDING)
	docker push $(REGISTRY)/landing:latest

push-all: push-admin push-core push-agent push-landing

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
		./internal/core/middleware/ \
		./internal/core/router/ \
		./internal/core/proxy/ \
		./internal/core/ws/ \
		-run 'TestReviewP0_|TestReviewP1_|TestReviewP2_|TestVerifyOIDCIDToken|TestTableReplace|TestValidateAdmin'
	@echo "==> SUCCESS test-prebuild"

lint:
	golangci-lint run ./...

# Checklist publication (hôte de build) — voir docs/audits/publication/host-runbook.md
prepublish-host:
	./ci/prepublish-host.sh $${STEP:-all}

# -----------------------------------------------------------------------------
# Nettoyage
# -----------------------------------------------------------------------------

clean:
	rm -f goproxify
	docker rmi $(REGISTRY)/admin:$(VERSION_ADMIN) \
	           $(REGISTRY)/core:$(VERSION_CORE) \
	           $(REGISTRY)/agent:$(VERSION_AGENT) \
	           $(REGISTRY)/landing:$(VERSION_LANDING) 2>/dev/null || true
