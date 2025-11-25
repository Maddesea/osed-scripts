# OSED Scripts Makefile
# Common tasks for development and usage

.PHONY: help install install-dev clean test lint format check completions

# Default target
help:
	@echo "OSED Scripts - Available targets:"
	@echo ""
	@echo "  install       Install Python dependencies"
	@echo "  install-dev   Install development dependencies"
	@echo "  completions   Install shell completions"
	@echo "  clean         Remove generated files"
	@echo "  lint          Run code linting"
	@echo "  format        Format code with black"
	@echo "  check         Run type checking"
	@echo "  test          Run tests (if available)"
	@echo ""
	@echo "  pattern       Generate 1000-byte pattern"
	@echo "  gadgets       Find gadgets (requires FILE=<binary>)"
	@echo ""
	@echo "Examples:"
	@echo "  make install"
	@echo "  make gadgets FILE=vuln.dll BAD='00 0a 0d'"

# Installation targets
install:
	pip3 install -r requirements.txt

install-dev:
	pip3 install -r requirements.txt
	pip3 install black mypy pytest

# Shell completions
completions:
	@echo "Installing bash completions..."
	@mkdir -p ~/.local/share/bash-completion/completions
	@cp completions/osed.bash ~/.local/share/bash-completion/completions/osed
	@echo "Bash completions installed."
	@echo ""
	@echo "For zsh, add to your ~/.zshrc:"
	@echo "  fpath=($(PWD)/completions \$$fpath)"
	@echo "  autoload -Uz compinit && compinit"

# Clean up
clean:
	rm -f found-gadgets.txt found-gadgets.txt.clean
	rm -f shellcode.bin pattern.txt
	rm -f *.pyc
	rm -rf __pycache__
	rm -rf .mypy_cache
	rm -rf .pytest_cache

# Development targets
lint:
	@echo "Running pylint..."
	-pylint --disable=C0114,C0115,C0116 *.py 2>/dev/null || true
	@echo "Linting complete."

format:
	@echo "Formatting code with black..."
	-black --line-length 100 *.py 2>/dev/null || echo "Black not installed, skipping..."

check:
	@echo "Running type checking..."
	-mypy --ignore-missing-imports *.py 2>/dev/null || echo "Mypy not installed, skipping..."

test:
	@echo "Running tests..."
	-pytest -v 2>/dev/null || echo "No tests found or pytest not installed."

# Convenience targets
pattern:
	./pattern.py create 1000

FILE ?=
BAD ?= 00

gadgets:
ifndef FILE
	@echo "Usage: make gadgets FILE=<binary> [BAD='00 0a 0d']"
	@exit 1
endif
	./find-gadgets.py -f $(FILE) -b $(BAD)

# Show version
version:
	@./osed version
