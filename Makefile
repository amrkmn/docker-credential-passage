.PHONY: build test clean lint install

BUILD_DIR := bin
BINARY_NAME := docker-credential-passage

build:
	@echo "+ $@"
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) passage/cmd/main.go

test:
	@echo "+ $@"
	@go test -v ./...

clean:
	@echo "+ $@"
	@rm -rf $(BUILD_DIR)

lint:
	@echo "+ $@"
	@go vet ./...

install: build
	@echo "+ $@"
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

test-integration:
	@echo "+ $@"
	@go test -v -tags=integration ./passage/
