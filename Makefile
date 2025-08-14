.PHONY: help install test test-specific test-coverage lint format type-check security-check clean build publish-test publish

# Default target
help:
	@echo "Available commands:"
	@echo "  install                              - Install development dependencies"
	@echo "  test                                 - Run tests"
	@echo "  test-specific ARGS="/path/to/file"   - Run tests for a specific file or class."
	@echo "  test-coverage                        - Run tests with coverage report"
	@echo "  lint                                 - Run flake8 linter"
	@echo "  format                               - Auto-format code with black and isort"
	@echo "  type-check                           - Run mypy type checking"
	@echo "  security-check                       - Run security vulnerability checks"
	@echo "  clean                                - Cleaning virtual environment and build artifacts"
	@echo "  build                                - Build distribution packages"
	@echo "  publish-test                         - Publish to TestPyPI"
	@echo "  publish                              - Publish to PyPI"
	@echo "  help                                 - Show this help message"

# Installation
install:
	@echo "Creating virtual environment..."
	python3 -m venv .venv
	@echo "Upgrading pip..."
	.venv/bin/pip install --upgrade pip
	@echo "Installing development dependencies..."
	.venv/bin/pip install -e ".[dev]"
	@echo ""
	@echo "✅ Setup complete!"

# Testing
test:
	@echo "🧪 Running tests..."
	.venv/bin/python -m pytest tests/ -x -s
	@echo "✅ Tests completed!"

test-specific:
	@echo "🧪 Running specific tests: $(ARGS)"
	.venv/bin/python -m pytest -x -s $(ARGS)
	@echo "✅ Specific tests completed!"

test-coverage:
	@echo "🧪 Running tests with coverage report..."
	.venv/bin/python -m pytest tests/ --cov=wristband --cov-report=term-missing
	@echo "✅ Coverage report completed!"

# Code Quality
lint:
	@echo "Running flake8 linter..."
	.venv/bin/python -m flake8 src tests
	@echo "✅ Linting complete!"

format:
	@echo "Formatting code with isort and black..."
	.venv/bin/python -m isort src tests
	.venv/bin/python -m black src tests
	@echo "✅ Code formatting complete!"

type-check:
	@echo "Running mypy type checking..."
	.venv/bin/python -m mypy src
	@echo "✅ Type checking complete!"

# Security checks
security-check:
	@echo "🔍 Checking dependencies for known vulnerabilities..."
	.venv/bin/python -m pip_audit
	@echo ""
	@echo "🔍 Scanning source code for security issues..."
	.venv/bin/python -m bandit -r src/
	@echo ""
	@echo "✅ Security checks complete!"

# Build and distribution
clean:
	@echo "Cleaning virtual environment and build artifacts..."
	rm -rf .venv/ build/ dist/ *.egg-info/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	@echo "✅ Cleanup complete."

build:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	@echo "Building distribution packages..."
	.venv/bin/python -m build
	@echo "✅ Build complete."

# Publishing
publish-test: build
	@echo "📦 Publishing to TestPyPI..."
	.venv/bin/python -m twine upload --repository testpypi dist/*
	@echo "✅ Published to TestPyPI successfully!"

publish: build
	@echo "⚠️  Publishing to PyPI! Make sure you're ready..."
	@read -p "Continue? (y/N): " confirm && [ "$confirm" = "y" ]
	.venv/bin/python -m twine upload dist/*
	@echo "✅ Publish complete."
