

import os
from tendril.config import AUTH0_NAMESPACE
os.environ['AUTH0_RULE_NAMESPACE'] = AUTH0_NAMESPACE

from fastapi import Security
from fastapi_auth0 import Auth0, Auth0User
from tendril.config import AUTH0_DOMAIN
from tendril.config import AUTH0_AUDIENCE

from tendril.authz import scopes
from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


logger.info("Using auth0 parameters:\n"
            "  - domain    {} \n"
            "  - audience  {} \n"
            "  - namespace {} ".format(AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_NAMESPACE))

auth = Auth0(domain=AUTH0_DOMAIN,
             api_audience=AUTH0_AUDIENCE,
             scopes=scopes.scopes)


authn_dependency = auth.implicit_scheme
AuthUserModel = Auth0User


def auth_spec(scopes=None):
    kwargs = {}
    if scopes:
        kwargs['scopes'] = scopes
    return Security(auth.get_user, **kwargs)


def get_user_profile(user: AuthUserModel):
    return {}
