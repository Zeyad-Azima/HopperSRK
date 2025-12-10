#
# Unified Makefile for HopperSRK - Hopper Security Researchers Kit
# Builds and installs all 12 security analyzer plugins
#
# Copyright (c) 2025 Zeyad Azima. All rights reserved.
#

# Colors for output
RED     := \033[0;31m
GREEN   := \033[0;32m
YELLOW  := \033[1;33m
BLUE    := \033[0;34m
CYAN    := \033[0;36m
RESET   := \033[0m

# Plugin directories
PLUGINS := FileOpAnalyzer \
           XPCAnalyzer \
           NetworkAnalyzer \
           MachIPCAnalyzer \
           KeychainAnalyzer \
           ProcessInjectionAnalyzer \
           AntiAnalysisDetector \
           PersistenceAnalyzer \
           C2Analyzer \
           RootkitDetector \
           PrivilegeEscalationDetector \
           SyscallAnalyzer

.PHONY: all build install clean help $(PLUGINS)

# Default target
all: build

# Build all plugins
build:
	@echo ""
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║  HopperSRK - Hopper Security Researchers Kit v2.0.0          ║$(RESET)"
	@echo "$(BLUE)║  Building All Security Analyzer Plugins                       ║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@total=12; \
	current=0; \
	for plugin in $(PLUGINS); do \
		current=$$((current + 1)); \
		echo "$(CYAN)[$$current/$$total]$(RESET) Building $$plugin..."; \
		if [ -f "$$plugin/Makefile" ]; then \
			$(MAKE) -C $$plugin all || exit 1; \
		else \
			echo "$(RED)  ✗ No Makefile found in $$plugin$(RESET)"; \
			exit 1; \
		fi; \
		echo "$(GREEN)  ✓ $$plugin built successfully$(RESET)"; \
		echo ""; \
	done
	@echo "$(GREEN)╔════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║  All 12 Plugins Built Successfully!                           ║$(RESET)"
	@echo "$(GREEN)╚════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""

# Install all plugins
install: build
	@echo ""
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║  Installing HopperSRK Plugins                                  ║$(RESET)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@total=12; \
	current=0; \
	for plugin in $(PLUGINS); do \
		current=$$((current + 1)); \
		echo "$(CYAN)[$$current/$$total]$(RESET) Installing $$plugin..."; \
		if [ -f "$$plugin/Makefile" ]; then \
			$(MAKE) -C $$plugin install || exit 1; \
		fi; \
		echo "$(GREEN)  ✓ $$plugin installed$(RESET)"; \
	done
	@echo ""
	@echo "$(GREEN)╔════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║  Installation Complete!                                        ║$(RESET)"
	@echo "$(GREEN)╚════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Installed Plugins:$(RESET)"
	@echo "  • File Operations Analyzer"
	@echo "  • XPC/IPC Communication Analyzer"
	@echo "  • Network Operations Analyzer"
	@echo "  • Mach IPC Analyzer"
	@echo "  • Keychain & Credential Analyzer"
	@echo "  • Process Injection Detector"
	@echo "  • Anti-Analysis Detector"
	@echo "  • Persistence Analyzer"
	@echo "  • C2 Communication Analyzer"
	@echo "  • Rootkit Detector"
	@echo "  • Privilege Escalation Detector"
	@echo "  • System Call Analyzer"
	@echo ""
	@echo "$(CYAN)Note:$(RESET) Restart Hopper Disassembler to load all plugins"
	@echo "$(CYAN)Access:$(RESET) Tools → [Plugin Name]"
	@echo ""

# Clean all build artifacts
clean:
	@echo "$(BLUE)Cleaning all plugin build artifacts...$(RESET)"
	@for plugin in $(PLUGINS); do \
		if [ -f "$$plugin/Makefile" ]; then \
			$(MAKE) -C $$plugin clean; \
		fi; \
	done
	@echo "$(GREEN)✓ All build artifacts cleaned$(RESET)"

# Build individual plugin
$(PLUGINS):
	@echo "$(CYAN)Building $@...$(RESET)"
	@$(MAKE) -C $@ all
	@echo "$(GREEN)✓ $@ built successfully$(RESET)"

# Help target
help:
	@echo ""
	@echo "$(BLUE)HopperSRK - Hopper Security Researchers Kit$(RESET)"
	@echo "$(BLUE)Unified Build System for Security Analyzer Plugins$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(RESET)"
	@echo "  $(GREEN)make$(RESET)          - Build all 12 plugins"
	@echo "  $(GREEN)make install$(RESET)  - Build and install all plugins"
	@echo "  $(GREEN)make clean$(RESET)    - Clean all build artifacts"
	@echo "  $(GREEN)make help$(RESET)     - Show this help message"
	@echo ""
	@echo "$(YELLOW)Individual plugins:$(RESET)"
	@for plugin in $(PLUGINS); do \
		echo "  $(GREEN)make $$plugin$(RESET) - Build only $$plugin"; \
	done
	@echo ""
	@echo "$(YELLOW)Plugins included:$(RESET)"
	@echo "  1.  File Operations Analyzer"
	@echo "  2.  XPC/IPC Communication Analyzer"
	@echo "  3.  Network Operations Analyzer"
	@echo "  4.  Mach IPC Analyzer"
	@echo "  5.  Keychain & Credential Analyzer"
	@echo "  6.  Process Injection Detector"
	@echo "  7.  Anti-Analysis Detector"
	@echo "  8.  Persistence Analyzer"
	@echo "  9.  C2 Communication Analyzer"
	@echo "  10. Rootkit Detector"
	@echo "  11. Privilege Escalation Detector"
	@echo "  12. System Call Analyzer"
	@echo ""
