

from tendril.authn.auth0 import Auth0PythonClient
from tendril.authn.auth0 import management_api
from tendril.config import AUTH0_AUDIENCE_ID


@management_api
def get_resource_servers(auth0: Auth0PythonClient):
    return auth0.resource_servers


def get_resource_server():
    return get_resource_servers().get(AUTH0_AUDIENCE_ID)


def get_current_scopes():
    return {x['value']: x['description'] for x in get_resource_server()['scopes']}


def commit_scopes(scopes):
    rs = get_resource_servers()
    rs.update(AUTH0_AUDIENCE_ID,
              {'scopes': [{'value': k, 'description': v}
                          for k, v in scopes.items()]})
