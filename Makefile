IMAGE_REPOSITORY ?= ghcr.io/0xch4z/benchmark-backend
IMAGE_TAG ?= latest
IMAGE := $(IMAGE_REPOSITORY):$(IMAGE_TAG)

CONTAINER_TOOL ?= docker

.PHONY: build
build:
	@CGO_ENABLED=0 go build \
		-trimpath \
		-buildvcs=false \
		-ldflags="-s -w" \
		-o benchmark-backend .

.PHONY: docker-build
docker-build:
	$(CONTAINER_TOOL) build -t $(IMAGE) .

.PHONY: docker-push
docker-push:
	$(CONTAINER_TOOL) push $(IMAGE)

.PHONY: docker-build-push
docker-build-push: docker-build docker-push

CONTAINER_NAME ?= benchmark-backend

.PHONY: docker-build
docker-run:
	$(CONTAINER_TOOL) rm --force $(CONTAINER_NAME) | true
	$(CONTAINER_TOOL) run --name $(CONTAINER_NAME) -d -p "8080:8080" $(IMAGE)
