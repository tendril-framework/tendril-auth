

import string
import secrets

from tendril.config import AUTH_MECHANIZED_USER_DOMAIN
from tendril.config import AUTH_MECHANIZED_PROVIDER

from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)


if AUTH_MECHANIZED_PROVIDER == "auth0":
    logger.info("Using the auth0 auth provider for mechanized users")
    from .providers import auth0 as MechanizedAuthProvider, stytch as MechanizedAuthProvider

    mechnized_provider_name = 'auth0'
if AUTH_MECHANIZED_PROVIDER == "stytch":
    logger.info("Using the stytch auth provider for mechanized users")
    mechanized_provider_name = 'stytch'
else:
    raise ImportError("AUTH_MECHANIZED_PROVIDER {} not recognized".format(AUTH_MECHANIZED_PROVIDER))


mechanized_authn_dependency = MechanizedAuthProvider.authn_dependency
AuthMechanizedUserModel = MechanizedAuthProvider.AuthUserModel
mechanized_auth_spec = MechanizedAuthProvider.auth_spec
get_mechanized_provider_user_profile = MechanizedAuthProvider.get_mechanized_user_profile


def _generate_password(length=32):
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password


def _get_mechanized_user_username(username, prefix):
    return f'{prefix}-{username}'


def _get_mechanized_user_email(username, prefix):
    return f'{username}@{prefix}.{AUTH_MECHANIZED_USER_DOMAIN}'


def _get_mechanized_user_name(username, prefix):
    return f'{prefix} {username}'


def create_mechanized_user(username, prefix, role=None, password=None):
    if not password:
        password = _generate_password()
    MechanizedAuthProvider.create_user(
        email=_get_mechanized_user_email(username, prefix),
        username=_get_mechanized_user_username(username, prefix),
        name=_get_mechanized_user_name(username, prefix),
        role=role,
        password=password, mechanized=True
    )
    return password


def find_mechanized_user_by_email(email):
    return MechanizedAuthProvider.find_user_by_email(email, mechanized=True)


def set_mechanized_user_password(user_id, password=None):
    if not password:
        password = _generate_password()
    MechanizedAuthProvider.set_user_password(user_id, password, mechanized=True)
    return password
