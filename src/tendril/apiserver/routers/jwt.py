

from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi import Depends

from tendril.authn.users import authn_dependency
from tendril.authn.users import AuthUserModel
from tendril.authn.users import auth_spec
from tendril.authn.users import verify_user_registration
from tendril.authn.users import get_user_profile
from tendril.authn.users import get_user_stub

from tendril.jwt.signer import generate
from tendril.config import AUTH_JWKS_PATH


jwt_services = APIRouter(prefix='/jwt',
                         tags=["JWT Services"])


@jwt_services.get("/jwks.json")
async def jwks():
    return FileResponse(AUTH_JWKS_PATH)


@jwt_services.get("/{domain}", dependencies=[Depends(authn_dependency),
                                                   auth_spec()])
async def get_domain_token(domain: str, user: AuthUserModel = auth_spec()):
    return {'jwt': generate(domain, user)}


routers = [
    jwt_services
]
