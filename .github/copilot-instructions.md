# AI Agent Instructions for secure-coding-mcp

## Project Overview
This is a Model Context Protocol (MCP) server designed to help AI agents write better and safer code. The project aims to provide guidance and tooling for implementing secure coding practices.

## Project Structure
```
.
├── src/                    # Source code directory
│   └── __init__.py         # Package initialization
├── tests/                  # Test files directory
│   └── __init__.py        # Test package initialization
├── pyproject.toml         # Python project configuration and dependencies
└── README.md             # Project documentation
```

## Development Environment
- Python version: >=3.13
- Key dependency: mcp[cli] ~=1.16.0
- Package and environment management: uv
- Type checking: mypy with strict settings

## Development Workflow
1. **Environment Setup**
   ```bash
   # We use uv exclusively for environment and dependency management
   uv venv
   source .venv/bin/activate  # On Unix/macOS
   
   # Install dependencies
   uv sync

   # Add new dependencies
   uv add <package-name>
   ```

2. **Running the Server**
   ```bash
   # Run the server in development mode
   uv run mcp dev src/secure_coding_server.py
   ```

3. **Testing**
   ```bash
   # Run the test suite with pytest
   uv run pytest
   
   # Run tests with coverage reporting
   uv run pytest --cov=src/secure_coding_mcp
   ```

4. **MCP Server Implementation**
   - The server will be implemented in the `src/` package
   - Implementation should follow modular design with separate modules for different concerns
   - Tests should be placed in parallel structure under `tests/`
   - Follow MCP protocol specifications for request/response handling
   - Focus on secure coding analysis and recommendations

## Key Patterns and Conventions
1. **Security Focus**
   - All code analysis and recommendations should prioritize security best practices
   - Consider OWASP guidelines and common security vulnerabilities
   - Provide specific, actionable guidance for secure coding

2. **MCP Protocol**
   - Implement handlers for MCP protocol methods
   - Ensure proper error handling and validation
   - Use type hints and docstrings for clear API documentation

3. **Code Quality**
   - Write testable, modular code with 100% test coverage
   - All code changes must include corresponding pytest unit tests
   - Test files should mirror the source structure under `tests/`
   - Tests must be type-checked and follow the same quality standards as source code
   - Extensive use of Python type hints with mypy validation
   - Prioritize newer language features and typing capabilities, e.g. use `str | None` instead of `Optional[str]`
   - All functions and classes must be fully typed
   - Code must be linted with ruff
   - Code formatting is managed by ruff
   - Import sorting is handled by isort
   - Do not use emojis in code or comments

4. **Testing changes**
   - All code changes must be tested by running:
        ```bash
        uv run ruff format .
        uv run isort src/ tests/
        uv run ruff check src/ tests/
        uv run pytest
        ```


## To Be Implemented
- [ ] MCP request handlers
- [ ] Security analysis logic
- [ ] Code improvement suggestions
- [ ] Test suite
- [ ] Documentation

## Need Help?
Review the following resources:
- Model Context Protocol documentation
- OWASP Secure Coding Guidelines
- Python Security Best Practices

This project is in early development. As patterns and conventions emerge, this guide will be updated accordingly.