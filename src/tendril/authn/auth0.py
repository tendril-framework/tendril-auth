

from fastapi import Security
from fastapi_auth0 import Auth0, Auth0User
from tendril.config import AUTH0_DOMAIN
from tendril.config import AUTH0_AUDIENCE

from tendril.authz import scopes


auth = Auth0(domain=AUTH0_DOMAIN,
             api_audience=AUTH0_AUDIENCE,
             scopes=scopes.scopes)


authn_dependency = auth.implicit_scheme
AuthUserModel = Auth0User


def auth_spec(scopes=None):
    if not scopes:
        return Security(auth.get_user)
    else:
        return Security(auth.get_user, scopes=scopes)
