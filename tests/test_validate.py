import pytest

from scitoken_http_auth import validate

from .util import *


def test_validator_init():
    v = validate.Validator(['foo'], 'aud', '/base/path')
    assert 'foo' in v.enforcers
    assert v.audience == 'aud'
    assert v.base_path == '/base/path'

def test_validator_root_path(make_token):
    raw_tok = make_token(scope='read:/', issuer='issuer', audience='aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_bad_raw_token(make_token):
    raw_tok = 'blahblah'

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid token'):
        tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_bad_issuer(make_token):
    raw_tok = make_token(scope='read:/foo/', issuer='bad_issuer', audience='aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid token issuer'):
        tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_bad_issuer2(make_token):
    raw_tok = make_token(scope='read:/foo/', issuer='issuer', audience='aud')

    v = validate.Validator(['issuer2'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid token issuer'):
        tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_bad_audience(make_token):
    raw_tok = make_token(scope='read:/foo/', issuer='issuer', audience='bad_aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid token'):
        tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_invalid_op(make_token):
    raw_tok = make_token(scope='read:/', issuer='issuer', audience='aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid authorization'):
        tok = v(raw_tok, 'PUT', '/base/path/')

def test_validator_invalid_path(make_token):
    raw_tok = make_token(scope='read:/foo/', issuer='issuer', audience='aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    with pytest.raises(validate.Error, match='invalid authorization'):
        tok = v(raw_tok, 'GET', '/base/path/')

def test_validator_two_scopes(make_token):
    raw_tok = make_token(scope='read:/ write:/', issuer='issuer', audience='aud')

    v = validate.Validator(['issuer'], 'aud', '/base/path')
    tok = v(raw_tok, 'GET', '/base/path/')
    tok = v(raw_tok, 'PUT', '/base/path/foo')
    tok = v(raw_tok, 'COPY', '/base/path/bar')
