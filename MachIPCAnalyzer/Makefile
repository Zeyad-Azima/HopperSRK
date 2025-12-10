# Makefile for Mach IPC Analyzer Hopper Plugin
# Copyright (c) 2025 Zeyad Azima. All rights reserved.

PLUGIN_NAME = MachIPCAnalyzer
BUNDLE_NAME = $(PLUGIN_NAME).hopperTool
SDK_PATH = ../HopperSDK

# Build directories
BUILD_DIR = build
BUNDLE_DIR = $(BUILD_DIR)/$(BUNDLE_NAME)
MACOS_DIR = $(BUNDLE_DIR)/Contents/MacOS
RESOURCES_DIR = $(BUNDLE_DIR)/Contents/Resources

# Installation paths
INSTALL_DIR_V4 = $(HOME)/Library/Application\ Support/Hopper/Plugins/v4/Tools
INSTALL_DIR_V5 = $(HOME)/Library/Application\ Support/Hopper/Plugins/v5/Tools

# Compiler settings
CC = clang
CFLAGS = -fmodules -fobjc-arc -I$(SDK_PATH)
FRAMEWORKS = -framework Foundation
LDFLAGS = -bundle

# Source files
SOURCES = $(PLUGIN_NAME).m
HEADERS = $(PLUGIN_NAME).h

# Colors for output
GREEN = \\033[0;32m
YELLOW = \\033[1;33m
NC = \\033[0m

.PHONY: all clean install uninstall

all: $(BUNDLE_DIR)

$(BUNDLE_DIR): $(SOURCES) $(HEADERS) Info.plist
	@echo "$(YELLOW)[1/4]$(NC) Creating bundle structure..."
	@mkdir -p $(MACOS_DIR)
	@mkdir -p $(RESOURCES_DIR)

	@echo "$(YELLOW)[2/4]$(NC) Compiling plugin..."
	@$(CC) $(CFLAGS) $(FRAMEWORKS) $(LDFLAGS) \
		-o $(MACOS_DIR)/$(PLUGIN_NAME) \
		$(SOURCES)

	@echo "$(YELLOW)[3/4]$(NC) Copying Info.plist..."
	@cp Info.plist $(BUNDLE_DIR)/Contents/

	@echo "$(YELLOW)[4/4]$(NC) Build complete!"
	@echo "$(GREEN)✓$(NC) Plugin bundle: $(BUNDLE_DIR)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) *.o
	@echo "$(GREEN)✓$(NC) Clean complete"

install: all
	@echo "$(YELLOW)Installing plugin...$(NC)"
	@mkdir -p $(INSTALL_DIR_V4)
	@mkdir -p $(INSTALL_DIR_V5)
	@rm -rf $(INSTALL_DIR_V4)/$(BUNDLE_NAME)
	@rm -rf $(INSTALL_DIR_V5)/$(BUNDLE_NAME)
	@cp -R $(BUNDLE_DIR) $(INSTALL_DIR_V4)/
	@cp -R $(BUNDLE_DIR) $(INSTALL_DIR_V5)/
	@echo "$(GREEN)✓$(NC) Plugin installed to v4: $(INSTALL_DIR_V4)/$(BUNDLE_NAME)"
	@echo "$(GREEN)✓$(NC) Plugin installed to v5: $(INSTALL_DIR_V5)/$(BUNDLE_NAME)"
	@echo ""
	@echo "$(YELLOW)Note:$(NC) Please restart Hopper Disassembler for the plugin to load."

uninstall:
	@echo "Uninstalling plugin..."
	@rm -rf $(INSTALL_DIR_V4)/$(BUNDLE_NAME)
	@rm -rf $(INSTALL_DIR_V5)/$(BUNDLE_NAME)
	@echo "$(GREEN)✓$(NC) Plugin uninstalled"

help:
	@echo "Mach IPC Analyzer Plugin - Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the plugin bundle"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make install  - Build and install plugin to Hopper"
	@echo "  make uninstall - Remove plugin from Hopper"
	@echo "  make help     - Show this help message"
