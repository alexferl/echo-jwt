.PHONY: dev test cover cover-html tidy fmt pre-commit

.DEFAULT: help
help:
	@echo "make dev"
	@echo "	setup development environment"
	@echo "make test"
	@echo "	run go test"
	@echo "make cover"
	@echo "	run go test with -cover"
	@echo "make cover-html"
	@echo "	run go test with -cover and show HTML"
	@echo "make tidy"
	@echo "	run go mod tidy"
	@echo "make fmt"
	@echo "	run gofumpt"
	@echo "make pre-commit"
	@echo "	run pre-commit hooks"

check-gofumpt:
ifeq (, $(shell which gofumpt))
	$(error "No gofumpt in $(PATH), gofumpt (https://pkg.go.dev/mvdan.cc/gofumpt) is required")
endif

check-pre-commit:
ifeq (, $(shell which pre-commit))
	$(error "No pre-commit in $(PATH), pre-commit (https://pre-commit.com) is required")
endif

dev: check-pre-commit check-gofumpt
	pre-commit install

test:
	go test -v ./...

cover:
	go test -cover -v ./...

cover-html:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

tidy:
	go mod tidy

fmt: check-gofumpt
	gofumpt -l -w .

pre-commit: check-pre-commit
	pre-commit
