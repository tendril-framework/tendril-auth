

from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi import Depends

from tendril.authn.users import security
from tendril.authn.users import swagger_auth
from tendril.authn.users import AuthUserModel
from tendril.authn.users import verify_user_registration
from tendril.authn.users import get_user_profile
from tendril.authn.users import get_user_stub

from tendril.jwt.sign import generate_token_async
from tendril.config import AUTH_JWKS_PATH
from tendril.config import AUTH_JWT_API_ENABLED


jwt_services = APIRouter(prefix='/jwt',
                         tags=["JWT Services"])


@jwt_services.get("/jwks.json")
async def jwks():
    return FileResponse(AUTH_JWKS_PATH)


@jwt_services.get("/{domain}", dependencies=[Depends(swagger_auth)])
async def get_domain_token(domain: str, user: AuthUserModel = security()):
    token = await generate_token_async(user, domain)
    return {'jwt': token}


if AUTH_JWT_API_ENABLED:
    routers = [
        jwt_services
    ]
else:
    routers = []
