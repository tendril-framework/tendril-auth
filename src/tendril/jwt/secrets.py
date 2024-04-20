

import json
from tendril.config import AUTH_JWKS_PATH
from tendril.config import AUTH_JWT_PUBLIC_KEY
from tendril.config import AUTH_JWT_PRIVATE_KEY
from tendril.utils import log
logger = log.get_logger(__name__)

public_key = None
private_key = None
jwks = None
kid = None


def _init():
    global jwks
    global kid
    global private_key
    global public_key

    with open(AUTH_JWKS_PATH, 'rb') as f:
        jwks = json.load(f)
        kid = jwks['kid']

    with open(AUTH_JWT_PUBLIC_KEY, 'rb') as f:
        public_key = f.read()

    with open(AUTH_JWT_PRIVATE_KEY, 'rb') as f:
        private_key = f.read()

try:
    _init()
except FileNotFoundError:
    logger.warn("JWT Secrets not found. "
                "JWTs cannot be generated in this component.")
