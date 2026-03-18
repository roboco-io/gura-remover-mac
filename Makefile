SHELL := /bin/zsh

SWIFT := swift
PRODUCT := gura
CONFIG ?= debug
PREFIX ?= /usr/local

ifeq ($(CONFIG),release)
BUILD_FLAGS := -c release
else
BUILD_FLAGS :=
endif

BUILD_DIR := .build/$(CONFIG)
BIN := $(BUILD_DIR)/$(PRODUCT)

.PHONY: help build rebuild test clean bin install exec scan list doctor history remove remove-safe restore signatures-update

help:
	@echo "Repository operations for gura"
	@echo ""
	@echo "Targets:"
	@echo "  make build CONFIG=debug|release         Build the gura binary"
	@echo "  make test                               Run Swift tests"
	@echo "  make clean                              Clean SwiftPM artifacts"
	@echo "  make doctor ARGS='--json'               Run doctor via compiled binary"
	@echo "  make scan ARGS='--json'                 Scan current system"
	@echo "  make list ARGS='--json'                 Print scan-style findings"
	@echo "  make history ARGS='--json'              Show backup history"
	@echo "  make remove ARGS='--id wizvera.delfino --yes'   Remove selected findings"
	@echo "  make remove-safe ARGS='--yes'           Remove all non-high-risk findings"
	@echo "  make restore ARGS='--session <id>'      Restore a backup session"
	@echo "  make signatures-update ARGS='--repo owner/repo --asset signatures.json'"
	@echo "  make exec ARGS='scan --json'            Run an arbitrary gura command"
	@echo "  make install PREFIX=/usr/local          Copy the built binary to PREFIX/bin"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make scan ARGS='--json'"
	@echo "  make remove ARGS='--id ahnlab.astx --yes --force-high-risk'"

$(BIN):
	$(SWIFT) build $(BUILD_FLAGS) --product $(PRODUCT)

build: $(BIN)

rebuild: clean build

test:
	$(SWIFT) test

clean:
	$(SWIFT) package clean

bin: build
	@echo $(BIN)

install: build
	install -d "$(PREFIX)/bin"
	install "$(BIN)" "$(PREFIX)/bin/$(PRODUCT)"
	@echo "Installed $(PRODUCT) to $(PREFIX)/bin/$(PRODUCT)"

exec: build
	"$(BIN)" $(ARGS)

scan: build
	"$(BIN)" scan $(ARGS)

list: build
	"$(BIN)" list $(ARGS)

doctor: build
	"$(BIN)" doctor $(ARGS)

history: build
	"$(BIN)" history $(ARGS)

remove: build
	"$(BIN)" remove $(ARGS)

remove-safe: build
	"$(BIN)" remove --all-safe $(ARGS)

restore: build
	"$(BIN)" restore $(ARGS)

signatures-update: build
	"$(BIN)" signatures update $(ARGS)
