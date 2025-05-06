APP_NAME := zzzxx
GOARCHS := amd64 arm64
OUTPUT_DIR := dist
IG_VERSION=v0.40.0
LDFLAGS := -X 	github.com/inspektor-gadget/inspektor-gadget/internal/version.version=v0.40.0 -w -s -extldflags "-static"
TAG ?= latest
GADGETS := trace_exec trace_dns
CONTAINER_REPO ?= github.com/dorser/zzzxxx/gadgets/
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

.PHONY: all clean

all: $(GADGETS) $(GOARCHS)

$(GADGETS):
	sudo -E ig image build \
		-t $(CONTAINER_REPO)$@:$(IMAGE_TAG) \
		--update-metadata gadgets/$@
	
	sudo -E ig image export $(CONTAINER_REPO)$@:$(IMAGE_TAG) build/$@.tar

$(GOARCHS):
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=$@ CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(OUTPUT_DIR)/$(APP_NAME)-linux-$@

clean:
	rm -rf $(OUTPUT_DIR)
