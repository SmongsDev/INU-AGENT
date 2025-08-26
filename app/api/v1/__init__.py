from fastapi import APIRouter
from . import routes_group
from . import routes_user

router = APIRouter()

router.include_router(routes_user.router, tags=["Users"])
router.include_router(routes_group.router, tags=["Groups"])