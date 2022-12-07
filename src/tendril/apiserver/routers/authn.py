

from fastapi import APIRouter
from fastapi import Depends

from tendril.authn import authn_dependency
from tendril.authn import AuthUserModel
from tendril.authn import auth_spec
from tendril.authn import verify_user_registration


user = APIRouter(prefix='/user',
                 tags=["User Authentication Services"],
                 dependencies=[Depends(authn_dependency),
                               auth_spec()])


@user.get("/verify")
async def verify(user: AuthUserModel = auth_spec()):
    verify_user_registration(user)
    return {"message": "Logged in User Verified."}


routers = [
    user
]
