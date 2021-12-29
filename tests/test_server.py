import socket
import pytest
from requests.exceptions import HTTPError
from rest_tools.client import RestClient

from scitoken_http_auth.server import create_server

from .util import *

@pytest.fixture
def port():
    """Get an ephemeral port number."""
    # https://unix.stackexchange.com/a/132524
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    addr = s.getsockname()
    ephemeral_port = addr[1]
    s.close()
    return ephemeral_port

@pytest.fixture
async def server(monkeypatch, port, make_token):
    monkeypatch.setenv('DEBUG', 'True')
    monkeypatch.setenv('PORT', str(port))

    monkeypatch.setenv('ISSUERS', 'issuer')
    monkeypatch.setenv('AUDIENCE', 'aud')
    monkeypatch.setenv('BASE_PATH', '/base')

    s = create_server()

    def fn(scope):
        token = make_token(scope, 'issuer', 'aud')
        return RestClient(f'http://localhost:{port}', token=token, timeout=0.1, retries=0)

    try:
        yield fn
    finally:
        await s.stop()


@pytest.mark.asyncio
async def test_server_root_path(server):
    client = server('read:/')
    await client.request('GET', '/', headers={
        'X-Original-Method': 'GET',
        'X-Original-URI': '/base/',
    })

@pytest.mark.asyncio
async def test_server_bad_method(server):
    client = server('read:/')
    with pytest.raises(HTTPError, match='invalid authorization'):
        await client.request('GET', '/', headers={
            'X-Original-Method': 'PUT',
            'X-Original-URI': '/base/',
        })

@pytest.mark.asyncio
async def test_server_two_scopes(server):
    client = server('read:/ write:/')
    await client.request('GET', '/', headers={
        'X-Original-Method': 'PUT',
        'X-Original-URI': '/base/',
    })

@pytest.mark.asyncio
async def test_server_post(server):
    client = server('read:/')
    with pytest.raises(HTTPError, match='405'):
        await client.request('POST', '/', headers={
            'X-Original-Method': 'GET',
            'X-Original-URI': '/base/',
        })
