APP_NAME := zzzxx
GOARCHS := amd64 arm64
OUTPUT_DIR := dist
IG_VERSION=v0.40.0
LDFLAGS := -X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=${IG_VERSION} -w -s -extldflags "-static"
TAG ?= latest
GADGET_NAME ?= trace_exec
CONTAINER_REPO ?= github.com/dorser/zzzxxx/gadgets/$(GADGET_NAME)
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

.PHONY: all clean build-gadget-$(GADGET_NAME)

all: build-gadget-$(GADGET_NAME) $(GOARCHS)

build-gadget-$(GADGET_NAME):
	sudo -E ig image build \
		-t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--update-metadata gadgets/$(GADGET_NAME)/
	
	sudo -E ig image export $(CONTAINER_REPO):$(IMAGE_TAG) build/$(GADGET_NAME).tar

$(GOARCHS):
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=$@ CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/$(APP_NAME)-linux-$@

clean:
	rm -rf $(OUTPUT_DIR)
