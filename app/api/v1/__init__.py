from fastapi import APIRouter
from . import routes_group
from . import routes_user
from . import routes_agentsetup
from . import routes_dashboard
from . import routes_aas
from . import routes_threats
from . import routes_alert
from . import routes_automation

router = APIRouter()

router.include_router(routes_user.router, tags=["Users"])
router.include_router(routes_group.router, tags=["Groups"])
router.include_router(routes_agentsetup.router, tags=["AgentFlow"])
router.include_router(routes_dashboard.router, tags=["DashBoard"])
router.include_router(routes_aas.router, tags=["AAS"])
router.include_router(routes_threats.router, tags=["Threats"])
router.include_router(routes_alert.router, tags=["Alerts"])
router.include_router(routes_automation.router, tags=["Automation"])