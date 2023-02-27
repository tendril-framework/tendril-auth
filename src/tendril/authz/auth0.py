

from tendril.authn.auth0 import Auth0PythonClient
from tendril.authn.auth0 import management_api
from tendril.authn.auth0 import cache
from tendril.config import AUTH0_AUDIENCE_ID


@management_api
def get_resource_servers(auth0: Auth0PythonClient):
    return auth0.resource_servers


@cache(namespace='auth0', ttl=86400, key=lambda *_: "resource_server")
def get_resource_server():
    return get_resource_servers().get(AUTH0_AUDIENCE_ID)


def get_current_scopes():
    return get_resource_server()['scopes']
