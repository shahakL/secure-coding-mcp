# secure-coding-mcp
Secure Coding MCP Server.

This server helps AI agents write more secure code by guiding them through a structured
thought process focused on security considerations and best practices.

Getting started
---------------

This project uses `uv` to manage the virtual environment and dependencies. The instructions below assume you have a working Python 3.13 installation and `uv` available.

Quick setup (local development)
-------------------------------

1. Create and activate the project virtual environment:

```bash
uv venv
source .venv/bin/activate
```

2. Install project dependencies (uses the editable install configured in pyproject.toml):

```bash
uv sync
```

Linting, formatting & static checks
----------------------------------

We use `ruff` for linting/formatting, `isort` for import sorting, and `mypy` for static typing.

Run the formatting and linting pipeline locally:

```bash
# Format files
uv run ruff format .

# Sort imports
uv run isort .

# Lint (ruff)
uv run ruff check .

# Type-check
uv run mypy .
```

Running tests
-------------

Unit tests are in `tests/unittests/` and use `pytest`. Run the test suite with:

```bash
uv run pytest tests/ -q
```

Contributing
------------

Please follow the existing code style and add unit tests for new behavior. Run the linting and tests locally before opening a PR.

