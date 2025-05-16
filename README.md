# fastapi-auth
SDK for integrating your Python FastAPI application with Wristband. Handles user authentication and token management.

## Getting Started
**SET PYPI TOKEN**
```bash
poetry config pypi-token.pypi <your-token>
```

## CICD
- on pull to main CICD will run
    - if the version wasnt changed a version patch will be applied

**PULL FROM MAIN**
- ensure you pull from main as the CICD could bump the version of the pyproject.toml 
```bash
git fetch origin main
git merge origin/main
```


## Manual Publushing
**BUILD**
```bash
poetry build
```
**BUMP VERSION**
```bash
# Bump patch version (4.0.1 → 4.0.2)
poetry version patch

# Bump minor version (4.0.1 → 4.1.0)
poetry version minor

# Bump major version (4.0.1 → 5.0.0)
poetry version major
```
**PUBLISH**
```bash
poetry publish
```