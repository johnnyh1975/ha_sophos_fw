"""HTTP session for the XML API.

The Sophos firewall mishandles reused keep-alive connections: a request sent
on a pooled connection hangs until the timeout (field test of the first 1.1
beta: the last request of the startup burst timed out after 20 s, twice) or
fails with "Server disconnected" (v1.0.x). A ``Connection: close`` request
header does not help — aiohttp pools a connection based on the server's
response, and a server that keeps the connection open gets it reused
(reproduced in tests/test_sophos_client.py).

Home Assistant's shared session cannot be told not to pool, so the
integration injects a dedicated session whose connector closes every
connection after its response. SophosClient itself accepts any session.
"""
from __future__ import annotations

import aiohttp
from homeassistant.util.ssl import get_default_context, get_default_no_verify_context

from .const import XML_MAX_CONCURRENT_REQUESTS


def create_xml_session(verify_ssl: bool) -> aiohttp.ClientSession:
    """Return a session that never reuses a connection.

    The caller owns the session and must close it. HA's pre-built SSL
    contexts are used, so no certificate store is loaded in the event loop.
    """
    connector = aiohttp.TCPConnector(
        force_close=True,
        limit=XML_MAX_CONCURRENT_REQUESTS,
        ssl=get_default_context() if verify_ssl else get_default_no_verify_context(),
    )
    return aiohttp.ClientSession(connector=connector)
