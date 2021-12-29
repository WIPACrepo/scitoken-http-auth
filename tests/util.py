import pytest
import scitokens
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key


@pytest.fixture(autouse=True, scope="session")
def scitokens_cache_location(tmp_path_factory):
    """Specify cache location, instead of writing to $HOME"""
    tmp_path = tmp_path_factory.mktemp('cache')
    scitokens.utils.config.CONFIG_DEFAULTS['cache_location'] = str(tmp_path)

@pytest.fixture(scope="session")
def gen_keys():
    priv = generate_private_key(65537, 2048)
    pub = priv.public_key()
    return (priv, pub)

@pytest.fixture
def make_token(gen_keys):
    def func(scope, issuer, audience):
        tok = scitokens.SciToken(key=gen_keys[0], key_id='testing')
        tok['sub'] = 'testing'
        tok['scope'] = scope
        tok['iss'] = issuer
        tok['aud'] = audience
        raw_tok = tok.serialize()

        # add key to keycache so deserialization works
        keycache = scitokens.utils.keycache.KeyCache().getinstance()
        keycache.addkeyinfo(issuer, 'testing', gen_keys[1], 3600)

        return raw_tok
    yield func
