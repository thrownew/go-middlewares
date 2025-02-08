.DEFAULT_GOAL := build

.PHONY: build
build:
	go mod verify
	go build

.PHONY: test-unit
test-unit:
	go clean -testcache
	go test -race -v -run Unit ./...

.PHONY: lint
lint:
	golangci-lint run -v

.PHONY: lint-fix
lint-fix:
	goimports -local github.com/thrownew/go-middlewares -w .
	go fmt ./...
	golangci-lint run -v
