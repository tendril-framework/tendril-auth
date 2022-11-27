

from tendril.config import AUTH_PROVIDER
from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


if AUTH_PROVIDER == "auth0":
    logger.info("Using the auth0 auth provider")
    from . import auth0 as AuthProvider
else:
    raise ImportError("AUTH_PROVIDER {} not recognized".format(AUTH_PROVIDER))


authn_dependency = AuthProvider.authn_dependency
AuthUserModel = AuthProvider.AuthUserModel
auth_spec = AuthProvider.auth_spec
