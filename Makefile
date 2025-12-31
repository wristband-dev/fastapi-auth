.PHONY: help install test test-specific test-coverage lint format type-check security-check clean build publish-test publish

# Detect OS and set platform-specific variables
VENV := .venv

ifeq ($(OS),Windows_NT)
    PYTHON := py -3
    VENV_PY := $(VENV)/Scripts/python.exe
else
    PYTHON := python3
    VENV_PY := $(VENV)/bin/python
endif

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
	$(PYTHON) -m venv $(VENV)
	@echo "Upgrading pip..."
	$(VENV_PY) -m pip install --upgrade pip
	@echo "Installing development dependencies..."
	$(VENV_PY) -m pip install -e ".[dev]"
	@echo ""
	@echo "✅ Setup complete!"

# Testing
test:
	@echo "🧪 Running tests..."
	$(VENV_PY) -m pytest tests/ -x -s
	@echo "✅ Tests completed!"

test-specific:
	@echo "🧪 Running specific tests: $(ARGS)"
	$(VENV_PY) -m pytest -s $(ARGS)
	@echo "✅ Specific tests completed!"

test-coverage:
	@echo "🧪 Running tests with coverage report..."
	$(VENV_PY) -m pytest tests/ --cov=wristband --cov-report=term-missing
	@echo "✅ Coverage report completed!"

# Code Quality
lint:
	@echo "Running flake8 linter..."
	$(VENV_PY) -m flake8 src tests
	@echo "✅ Linting complete!"

format:
	@echo "Formatting code with isort and black..."
	$(VENV_PY) -m isort src tests
	$(VENV_PY) -m black src tests
	@echo "✅ Code formatting complete!"

type-check:
	@echo "Running mypy type checking..."
	$(VENV_PY) -m mypy src
	@echo "✅ Type checking complete!"

# Security checks
security-check:
	@echo "🔍 Checking dependencies for known vulnerabilities..."
	$(VENV_PY) -m pip_audit
	@echo ""
	@echo "🔍 Scanning source code for security issues..."
	$(VENV_PY) -m bandit -r src/
	@echo ""
	@echo "✅ Security checks complete!"

# Clean up virtual environment by removing the following:
#   - .venv/           Virtual environment directory
#   - build/           Build artifacts from setuptools
#   - dist/            Distribution packages (wheels, sdist)
#   - htmlcov/         HTML coverage reports
#   - .pytest_cache/   Pytest cache directory
#   - .mypy_cache/     Mypy type checker cache
#   - .coverage        Coverage data file
#   - *.egg-info/      Package metadata directories
#   - __pycache__/     Python bytecode cache directories (recursively)
#   - *.pyc            Compiled Python bytecode files (recursively)
clean:
	@echo "Cleaning virtual environment and build artifacts..."
	@$(PYTHON) -c "import shutil, pathlib; \
		dirs = ['.venv', 'build', 'dist', 'htmlcov', '.pytest_cache', '.mypy_cache']; \
		[shutil.rmtree(p, ignore_errors=True) for p in dirs]; \
		[p.unlink(missing_ok=True) for p in [pathlib.Path('.coverage')]]; \
		[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('*.egg-info')]; \
		[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; \
		[p.unlink() for p in pathlib.Path('.').rglob('*.pyc')]"
	@echo "✅ Cleanup complete."

# Build distribution packages
# Cleans build artifacts (build/, dist/, *.egg-info/, __pycache__/, *.pyc) before
# creating source distribution (sdist) and wheel packages in the dist/ directory.
build:
	@echo "Cleaning build artifacts..."
	@$(PYTHON) -c "import shutil, pathlib; \
		dirs = ['build', 'dist']; \
		[shutil.rmtree(p, ignore_errors=True) for p in dirs]; \
		[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('*.egg-info')]; \
		[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; \
		[p.unlink() for p in pathlib.Path('.').rglob('*.pyc')]"
	@echo "Building distribution packages..."
	$(VENV_PY) -m build
	@echo "✅ Build complete."

# Publishing
publish-test: build
	@echo "📦 Publishing to TestPyPI..."
	$(VENV_PY) -m twine upload --repository testpypi dist/*
	@echo "✅ Published to TestPyPI successfully!"

publish: build
	@echo "⚠️  Publishing to PyPI! Make sure you're ready..."
ifeq ($(OS),Windows_NT)
	@set /p confirm="Continue? (y/N): " && if /i "%confirm%" neq "y" exit /b 1
else
	@read -p "Continue? (y/N): " confirm && [ "$confirm" = "y" ]
endif
	$(VENV_PY) -m twine upload dist/*
	@echo "✅ Publish complete."
