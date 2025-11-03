"""
Tendril Authentication Provider — Stytch (Async)

This module integrates Stytch's Consumer API and Mechanized Users API
with Tendril’s authentication layer. It provides async FastAPI dependencies
for authentication, user profile resolution, and management.

Key principles:
 - Always verify tokens directly with Stytch (no caching of token validity)
 - Cache user profiles (fetched by user_id) to minimize network calls
 - Use Stytch’s native async client methods (*_async)

Configuration required in tendril.config:
  AUTH_STYTCH_PROJECT_ID
  AUTH_STYTCH_SECRET
  AUTH_STYTCH_ENVIRONMENT
  AUTH_STYTCH_MECHANIZED_PROJECT_ID
  AUTH_STYTCH_MECHANIZED_SECRET
  AUTH_STYTCH_MECHANIZED_ENVIRONMENT
"""
import re
import asyncio
import hashlib
from fastapi import Depends, Security, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from stytch.consumer.client import Client as StytchClient
from stytch.consumer.models.users import User as StytchUserModel
from stytch.core.response_base import StytchError

from tendril.utils.pydantic import TendrilTBaseModel
from tendril.jwt.sign import generate_token

from tendril.config import (
    AUTH_PROVIDER,
    AUTH_MECHANIZED_PROVIDER,
    AUTH_USERINFO_CACHING,
    AUTHZ_PROVIDER,
    AUTH_STYTCH_PROJECT_ID,
    AUTH_STYTCH_SECRET,
    AUTH_STYTCH_ENVIRONMENT,
    AUTH_STYTCH_MECHANIZED_PROJECT_ID,
    AUTH_STYTCH_MECHANIZED_SECRET,
    AUTH_STYTCH_MECHANIZED_ENVIRONMENT,
)

from tendril.utils import log
logger = log.get_logger(__name__, log.DEBUG)

if AUTH_USERINFO_CACHING == 'platform':
    logger.info("Using platform level caching for Stytch UserInfo")
    from tendril.caching import platform_cache as cache
else:
    logger.warning("Not caching Stytch UserInfo")
    from tendril.caching import no_cache as cache

security_scheme = HTTPBearer(auto_error=False)


# -----------------------------------------------------------------------------
# Client Initialization
# -----------------------------------------------------------------------------
stytch_client: StytchClient | None = None
stytch_mechanized_client: StytchClient | None = None


def _init_stytch_client(project_id, secret, environment, purpose):
    logger.debug(f"Initializing the stytch client for {purpose}")
    if not project_id or not secret:
        msg = f"Stytch configuration missing — cannot initialize auth provider for {purpose}."
        logger.error(msg)
        raise RuntimeError(msg)
    try:
        client = StytchClient(
            project_id=project_id, secret=secret, environment=environment
        )
        logger.info(f"Initialized Stytch Client for {purpose} with parameters:\n"
                    f"  - project      {project_id} \n"
                    f"  - environment  {environment} \n")
    except Exception as e:
        logger.exception(f"Failed to initialize Stytch client for {purpose}: %s", e)
        raise
    return client

def _init_stytch_user_client():
    global stytch_client
    stytch_client = _init_stytch_client(
        AUTH_STYTCH_PROJECT_ID,
        AUTH_STYTCH_SECRET,
        AUTH_STYTCH_ENVIRONMENT,
        "User Authentication"
    )

def _init_stytch_mechanised_client():
    global stytch_mechanized_client
    stytch_mechanized_client = _init_stytch_client(
        AUTH_STYTCH_MECHANIZED_PROJECT_ID,
        AUTH_STYTCH_MECHANIZED_SECRET,
        AUTH_STYTCH_MECHANIZED_ENVIRONMENT,
        "Mechanized Users"
    )

def init():
    """
    Initialize global Stytch client(s).
    Called automatically from tendril.authn.users.init()
    """
    if AUTH_PROVIDER == "stytch":
        _init_stytch_user_client()
    if AUTH_MECHANIZED_PROVIDER == "stytch":
        _init_stytch_mechanised_client()


# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def extract_bearer_token(authorization: str) -> str:
    """Extract Bearer token from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    match = re.match(r"^Bearer\s+(.+)$", authorization.strip(), re.I)
    if not match:
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")

    return match.group(1)

def gravatar_url(email: str, size: int = 200) -> str:
    if not email:
        return "https://www.gravatar.com/avatar/?d=identicon"
    hash_ = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_}?s={size}&d=identicon"


# -----------------------------------------------------------------------------
# Authentication (Consumers + Mechanized)
# -----------------------------------------------------------------------------
async def authenticate_stytch_token_async(
    token: str, mechanized: bool = False
) -> StytchUserModel:
    """
    Validate the given Stytch session token and return the associated user.
    mechanized=True uses the mechanized Stytch project.
    """
    client = stytch_mechanized_client if mechanized else stytch_client

    if not client:
        raise HTTPException(
            status_code=500, detail="Stytch client is not initialized for this mode"
        )

    logger.debug(
        "Authenticating %s token (async): prefix=%s...",
        "mechanized" if mechanized else "user",
        token[:10],
    )

    try:
        response = await client.sessions.authenticate_async(session_token=token)
        user = response.user
        logger.debug(
            "Authenticated %s token for user_id=%s email=%s",
            "mechanized" if mechanized else "consumer",
            user.user_id,
            user.emails[0].email if user.emails else "N/A",
        )
        return user
    except StytchError as e:
        logger.warning("Stytch token verification failed: %s", e)
        raise HTTPException(status_code=401, detail="Invalid or expired Stytch token")
    except Exception as e:
        logger.exception("Unexpected error verifying Stytch token: %s", e)
        raise HTTPException(status_code=500, detail="Internal authentication error")

# -----------------------------------------------------------------------------
# Standardized Interface for tendril.authn.users
# -----------------------------------------------------------------------------
AuthUserModel = StytchUserModel

# -----------------------------------------------------------------------------
# Cached User Profile Retrieval
# -----------------------------------------------------------------------------
@cache(namespace="userinfo", ttl=3600, key=lambda user_id: user_id)
async def get_user_profile(user_id: str, mechanized: bool = False) -> StytchUserModel:
    """
    Retrieve and cache the Stytch user profile by user_id.
    """
    client = stytch_mechanized_client if mechanized else stytch_client

    if not client:
        raise HTTPException(status_code=500, detail="Stytch client not initialized")

    logger.debug(
        "Fetching %s user profile for user_id=%s",
        "mechanized" if mechanized else "",
        user_id,
    )

    try:
        response = await client.users.get_async(user_id=user_id)
        user = response.user
        logger.debug(
            "Cached %s user profile for user_id=%s email=%s",
            "mechanized" if mechanized else "consumer",
            user.user_id,
            user.emails[0].email if user.emails else "N/A",
        )
        return user
    except StytchError as e:
        logger.warning(
            "Failed to fetch %s user profile for user_id=%s: %s",
            "mechanized" if mechanized else "consumer",
            user_id,
            e,
        )
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.exception("Unexpected error fetching Stytch user profile for %s: %s", user_id, e)
        raise HTTPException(status_code=500, detail="Internal user profile error")


@cache(namespace='userstub', ttl=86400, key=lambda user_id: user_id)
async def get_user_stub(user_id):
    profile = await get_user_profile(user_id)
    print(profile)

    if 'description' in profile.keys():
        return profile

    email = profile.emails[0].email if profile.emails else None
    nickname = profile.name.first_name or (
        email.split("@")[0] if email else f"user_{profile.user_id[-6:]}"
    )

    stub = {
        "name": f"{profile.name.first_name or ''} {profile.name.last_name or ''}".strip() or nickname,
        'nickname': nickname,
        'picture': gravatar_url(email),
        'user_id': profile.user_id,
    }

    logger.debug("Generated stub for user_id=%s: %s", profile.user_id, stub)
    return stub


# -----------------------------------------------------------------------------
# FastAPI Dependency Interface
# -----------------------------------------------------------------------------
async def authn_dependency(credentials: HTTPAuthorizationCredentials = Security(security_scheme),) -> StytchUserModel:
    """
    FastAPI dependency: verifies a Stytch bearer token and returns the user profile.

    Behavior:
      - Extracts and validates Bearer token from Authorization header.
      - Authenticates with Stytch asynchronously.
      - Raises 401 if token is invalid or expired.
    """
    if not credentials:
        logger.debug("authn_dependency: no Authorization header provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    token = credentials.credentials
    logger.debug("authn_dependency: received bearer token prefix=%s", token[:10])

    try:
        user = await authenticate_stytch_token_async(token)
    except StytchError as e:
        logger.warning("Stytch token verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Stytch token",
        ) from e
    except Exception as e:
        logger.exception("Unexpected error during Stytch authentication")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal authentication error",
        ) from e

    logger.debug("authn_dependency: authenticated user_id=%s", user.user_id)
    return user

async def mechanized_authn_dependency(credentials: HTTPAuthorizationCredentials = Security(security_scheme),) -> StytchUserModel:
    """
    FastAPI dependency: verifies a Stytch bearer token and returns the user profile.

    Behavior:
      - Extracts and validates Bearer token from Authorization header.
      - Authenticates with Stytch asynchronously.
      - Raises 401 if token is invalid or expired.
    """
    if not credentials:
        logger.debug("authn_dependency: no Authorization header provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    token = credentials.credentials
    logger.debug("authn_dependency: received bearer token prefix=%s", token[:10])

    try:
        user = await authenticate_stytch_token_async(token, mechanized=True)
    except StytchError as e:
        logger.warning("Stytch token verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Stytch token",
        ) from e
    except Exception as e:
        logger.exception("Unexpected error during Stytch authentication")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal authentication error",
        ) from e

    logger.debug("authn_dependency: authenticated user_id=%s", user.user_id)
    return user


# -----------------------------------------------------------------------------
# Security Spec for Endpoints
# -----------------------------------------------------------------------------
def auth_spec(scopes=None):
    kwargs = {}
    if scopes:
        logger.warning(f"Scopes {scopes} specified for stytch user security. The stytch "
                       f"provider does not support authn, so scopes specification is ignored. "
                       f"You probably want to use auth_spec from the tendril provider instead.")
    return Security(authn_dependency, **kwargs)


def mechanized_auth_spec(scopes=None):
    """
    Return a FastAPI Security dependency configured for mechanized users.
    """
    kwargs = {}
    if scopes:
        logger.warning(f"Scopes {scopes} specified for stytch mechanized user security. The stytch "
                       f"provider does not support authn, so scopes specification is ignored. "
                       f"You probably want to use auth_spec from the tendril provider instead.")
    return Security(mechanized_authn_dependency, **kwargs)
