"""
Server for scitoken http auth
"""

import logging

from tornado.web import RequestHandler, HTTPError
from rest_tools.server import RestServer, RestHandler
from rest_tools.utils import from_environment

from .validate import Validator


class Main(RestHandler):
    def initialize(self, validator, **kwargs):
        super().initialize(**kwargs)
        self.validator = validator

    async def get(self, *args):
        auth = self.request.headers.get('Authorization', '')
        method = self.request.headers.get('X-Original-Method', '')
        path = self.request.headers.get('X-Original-URI', '')

        parts = auth.split(' ', 1)
        if parts[0].lower() != 'bearer' or not len(parts) == 2:
            raise HTTPError(403, reason='must supply a bearer token')
        raw_token = parts[1]

        if token := self.validator(raw_token, method, path):
            if 'sub' not in token:
                raise HTTPError(403, reason='sub not in token')
            logging.info(f'valid request for user {token["sub"]}: {method}:{path}')
            self.set_header('REMOTE_USER', token['sub'])
            if uid := token.get('posix', {}).get('uid', None):
                self.set_header('X_UID', uid)
            if gid := token.get('posix', {}).get('gid', None):
                self.set_header('X_UID', gid)
            self.write('')
        else:
            self.send_error(403, 'not authorized')

def create_server():
    default_config = {
        'HOST': 'localhost',
        'PORT': 8080,
        'DEBUG': False,
        'ISSUERS': None,
        'AUDIENCE': None,
        'BASE_PATH': '/',
    }
    config = from_environment(default_config)

    rest_config = {
        'debug': config['DEBUG'],
        'validator': Validator(issuers=config['ISSUERS'].split(','),
                               audience=config['AUDIENCE'],
                               base_path=config['BASE_PATH']),
    }

    server = RestServer(debug=config['DEBUG'])
    server.add_route(r'/(.*)', Main, rest_config)

    server.startup(address=config['HOST'], port=config['PORT'])

    return server
