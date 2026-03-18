SHELL := /bin/zsh

SWIFT := swift
PRODUCT := gura
CONFIG ?= debug
PREFIX ?= /usr/local

ifeq ($(strip $(SUDO_USER)),)
SWIFT_RUNNER :=
else
SWIFT_RUNNER := sudo -u $(SUDO_USER)
endif

ifeq ($(CONFIG),release)
BUILD_FLAGS := -c release
else
BUILD_FLAGS :=
endif

BUILD_DIR := .build/$(CONFIG)
BIN := $(BUILD_DIR)/$(PRODUCT)

.PHONY: help build rebuild test clean bin install exec scan list doctor history remove remove-safe remove-all remove-all-dry-run restore signatures-update

help:
	@echo "gura Make targets"
	@echo ""
	@echo "Builds and runs the compiled .build/\$$(CONFIG)/gura binary."
	@echo "Use ARGS='...' to pass flags to the command."
	@echo ""
	@echo "Build/Test:"
	@echo "  make build CONFIG=debug|release         Build the gura binary"
	@echo "  make rebuild CONFIG=debug|release       Clean and rebuild"
	@echo "  make test                               Run Swift tests"
	@echo "  make clean                              Clean SwiftPM artifacts"
	@echo "  make bin                                Print compiled binary path"
	@echo "  make install PREFIX=/usr/local          Install compiled binary to PREFIX/bin"
	@echo ""
	@echo "Read-only operations:"
	@echo "  make doctor ARGS='--json'               Inspect permissions, tools, backups, signatures"
	@echo "  make scan ARGS='--json'                 Scan current system for detected modules"
	@echo "  make list ARGS='--json'                 Print scan-style findings"
	@echo "  make history ARGS='--json'              Show backup/restore history"
	@echo "  make signatures-update ARGS='--repo owner/repo --asset signatures.json'"
	@echo "                                         Download updated signature bundle"
	@echo ""
	@echo "Mutating operations:"
	@echo "  make remove ARGS='--id wizvera.delfino --yes'"
	@echo "                                         Remove selected finding IDs"
	@echo "  make remove-safe ARGS='--yes'           Remove all non-high-risk findings"
	@echo "  make remove-all                         Scan and remove all currently detected findings"
	@echo "  make remove-all-dry-run                 Preview full removal plan without deleting files"
	@echo "  make restore ARGS='--session <id>'      Restore a backup session"
	@echo ""
	@echo "Notes:"
	@echo "  - System-scope deletion usually requires sudo."
	@echo "  - High-risk items require --force-high-risk."
	@echo "  - Use --dry-run first when validating a removal plan."
	@echo "  - remove also stops matching processes, unregisters launchd services,"
	@echo "    forgets pkg receipts, and attempts system extension uninstall."
	@echo "  - When invoked via sudo, SwiftPM build/test/clean run as SUDO_USER to avoid"
	@echo "    root-owned files under .build."
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make scan ARGS='--json'"
	@echo "  make remove-safe ARGS='--yes --dry-run'"
	@echo "  make remove-all-dry-run"
	@echo "  sudo make remove-all"
	@echo "  make remove ARGS='--id wizvera.delfino --yes --dry-run'"
	@echo "  make remove ARGS='--id ahnlab.astx --yes --force-high-risk'"
	@echo "  sudo make remove ARGS='--id inca.nprotectonlinesecurity --yes --force-high-risk'"

$(BIN):
	$(SWIFT_RUNNER) $(SWIFT) build $(BUILD_FLAGS) --product $(PRODUCT)

build:
	$(SWIFT_RUNNER) $(SWIFT) build $(BUILD_FLAGS) --product $(PRODUCT)

rebuild: clean build

test:
	$(SWIFT_RUNNER) $(SWIFT) test

clean:
	$(SWIFT_RUNNER) $(SWIFT) package clean

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

remove-all-dry-run: build
	"$(BIN)" remove --all-safe --yes --dry-run
	@if "$(BIN)" scan --json | grep -q '"id" : "ahnlab.astx"'; then \
		"$(BIN)" remove --id ahnlab.astx --yes --dry-run --force-high-risk; \
	fi
	@if "$(BIN)" scan --json | grep -q '"id" : "inca.nprotectonlinesecurity"'; then \
		"$(BIN)" remove --id inca.nprotectonlinesecurity --yes --dry-run --force-high-risk; \
	fi

remove-all: build
	"$(BIN)" remove --all-safe --yes
	@if "$(BIN)" scan --json | grep -q '"id" : "ahnlab.astx"'; then \
		"$(BIN)" remove --id ahnlab.astx --yes --force-high-risk; \
	fi
	@if "$(BIN)" scan --json | grep -q '"id" : "inca.nprotectonlinesecurity"'; then \
		"$(BIN)" remove --id inca.nprotectonlinesecurity --yes --force-high-risk; \
	fi

restore: build
	"$(BIN)" restore $(ARGS)

signatures-update: build
	"$(BIN)" signatures update $(ARGS)
