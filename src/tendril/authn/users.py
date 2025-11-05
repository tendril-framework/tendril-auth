

import inspect
from tendril.utils.fsutils import load_provider
from tendril.config import AUTH_PROVIDER
from tendril.authz import domains

from .db.model import User
from .db.controller import register_provider
from .db.controller import register_user
from .db.controller import get_user_by_id

from .scaffold import wrap_security
from .scaffold import null_dependency

from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)

try:
    AuthProvider = load_provider(AUTH_PROVIDER, "tendril.authn.providers")
    provider_name = AUTH_PROVIDER
except ImportError as e:
    logger.critical(e)
    raise

# This motif is based on Auth0's auth_dependency, where auth0's implicit scheme is provided
# for swagger integration. If a provider does not need this, it this can be replaced with a
# dummy function that just returns None.
swagger_auth = getattr(AuthProvider, "swagger_auth", null_dependency)
security = wrap_security(provider_name, AuthProvider.security)
AuthUserModel = AuthProvider.AuthUserModel
get_provider_user_profile = AuthProvider.get_user_profile


def preprocess_user(user):
    if isinstance(user, AuthUserModel):
        user = user.id
    elif isinstance(user, User):
        user = user.id
    elif isinstance(user, int):
        user = get_user_by_id(user).puid
    return user


async def get_user_profile(user):
    user = preprocess_user(user)
    profile = {}

    result = get_provider_user_profile(user)
    if inspect.isawaitable(result):
        result = await result
    profile[provider_name] = result
    return profile


async def expand_user_stub(v, **kwargs):
    if inspect.isawaitable(v):
        v = await v
    if isinstance(v, str):
        return await get_user_stub(v)
    return v


async def get_user_stub(user):
    user = preprocess_user(user)
    result = AuthProvider.get_user_stub(user)
    if inspect.isawaitable(result):
        result = await result
    return result


async def get_user_email(user):
    profile = await get_user_profile(user)
    try:
        return profile[provider_name]['email']
    except KeyError:
        raise AttributeError(f"Could not find an email for user {user}")


def verify_user_registration(user, background_tasks=None):
    user_id = preprocess_user(user)
    user, first_login = register_user(user_id, provider_name)
    if background_tasks:
        background_tasks.add_task(domains.upsert,
                                  user=user,
                                  first_login=first_login)


def init():
    AuthProvider.init()
    register_provider(provider_name)


init()
