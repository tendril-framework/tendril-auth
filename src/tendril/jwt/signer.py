

import jwt
from datetime import datetime
from datetime import timedelta

from tendril.config import AUTH_JWT_ISSUER
from tendril.config import AUTH_JWT_TTL
from tendril.config import AUTH_JWT_VALIDITY
from tendril.config import AUTH_JWT_ALGORITHMS

from .secrets import private_key
from .secrets import kid


_domains = {}

def register_domain(domain, spec):
    global _domains
    _domains[domain] = spec


def generate(domain, user):
    global _domains
    if not domain in _domains.keys():
        raise Exception

    if not user:
        raise Exception

    spec = _domains[domain]

    payload = {
        'iss': AUTH_JWT_ISSUER,
        'dom': domain,
        'exp': datetime.utcnow() + timedelta(seconds=AUTH_JWT_VALIDITY + AUTH_JWT_TTL),
        'nbf': datetime.utcnow() + timedelta(seconds=AUTH_JWT_TTL),
        'iat': datetime.utcnow()
    }

    for claim, claim_spec in spec['claims'].items():
        if claim_spec == 'user_email':
            payload[claim] = user.email

    return jwt.encode(payload, private_key, algorithm=AUTH_JWT_ALGORITHMS[0], headers={'kid': kid})
