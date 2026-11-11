GO ?= go
VERSION ?= dev
IMAGE ?= kevgate-admit:$(VERSION)
PKGS := ./...

.PHONY: all build test race cover fuzz lint vet vuln helm demo-check docker clean

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X github.com/samiali38183/kevgate-admit/internal/app.Version=$(VERSION)" -o bin/kevgate-admit ./cmd/kevgate-admit

test:
	$(GO) test $(PKGS)

race:
	CGO_ENABLED=1 $(GO) test -race $(PKGS)

cover:
	$(GO) test $(PKGS) -covermode=atomic -coverprofile=coverage.txt
	$(GO) tool cover -func=coverage.txt | tail -1

fuzz:
	$(GO) test ./internal/trivy -run '^$$' -fuzz FuzzParse -fuzztime 30s
	$(GO) test ./internal/admission -run '^$$' -fuzz FuzzDecodeAndExtract -fuzztime 30s

vet:
	$(GO) vet $(PKGS)

lint:
	golangci-lint run $(PKGS)

vuln:
	govulncheck $(PKGS)

helm:
	helm lint --strict deploy/helm/kevgate-admit
	helm template kevgate-admit deploy/helm/kevgate-admit | kubeconform -strict -summary -

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -rf bin coverage.txt
