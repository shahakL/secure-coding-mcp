from collections.abc import AsyncGenerator

import pytest
from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session as client_session

import secure_coding_server


@pytest.fixture
def mcp_server() -> FastMCP:
    """Return the FastMCP instance exported by the installed module."""
    return secure_coding_server.mcp


@pytest.fixture
async def client_session_fixture(mcp_server: FastMCP) -> AsyncGenerator[ClientSession]:
    async with client_session(mcp_server._mcp_server) as client:
        yield client
