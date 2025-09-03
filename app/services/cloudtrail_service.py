from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple
from sqlalchemy import select
from app.schemas.events import Event
from app.db.session import get_db
from app.db.models import Event as EventModel, CloudTrail as CloudTrailModel

class CloudTrailService:
    def __init__(self, group_id):
        self.group_id = group_id

    def _build_actor_key(self, user_identity: dict, request_parameters: dict | None = None) -> Optional[str]:
        if not user_identity:
            return None
            
        # 1. ARN이 있는 경우 우선 사용
        arn = user_identity.get('arn')
        if arn:
            return arn
            
        # 2. 세션 컨텍스트의 발급자 ARN 확인
        session_issuer = (
            user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('arn')
        )
        if session_issuer:
            return session_issuer
            
        # 3. IAM 사용자 이름이 있는 경우
        user_name = user_identity.get('userName')
        account_id = user_identity.get('accountId')
        if user_name and account_id:
            return f"arn:aws:iam::{account_id}:user/{user_name}"
            
        # 4. Principal ID 확인
        principal_id = user_identity.get('principalId')
        if principal_id:
            return principal_id
            
        # 5. Access Key ID 확인
        access_key_id = user_identity.get('accessKeyId')
        if access_key_id:
            return f"ACCESS_KEY:{access_key_id}"
            
        # 6. 외부 인증 제공자 정보 확인
        identity_provider = user_identity.get('identityProvider')
        credential_id = user_identity.get('credentialId')
        if identity_provider and credential_id:
            return f"{identity_provider}:{credential_id}"
            
        # 7. 요청 파라미터에서 userArn 확인
        if request_parameters and isinstance(request_parameters, dict):
            rp_arn = request_parameters.get('userArn')
            if rp_arn:
                return rp_arn
                
        # 8. 계정 ID만 있는 경우
        if account_id:
            return f"AWS_ACCOUNT:{account_id}"
            
        return None

    async def get_actor_key_and_time(self, event_id) -> Tuple[Optional[str], Optional[datetime]]:
        db = next(get_db())
        try:
            ev = db.get(EventModel, event_id)
            if not ev or ev.group_id != self.group_id:
                return None, None
            ct = db.get(CloudTrailModel, event_id)
            if not ct:
                return None, ev.created_at
            actor_key = self._build_actor_key(ct.user_identity, getattr(ct, 'request_parameters', None))
            occurred_at = getattr(ct, 'event_time', None) or ev.created_at
            return actor_key, occurred_at
        finally:
            db.close()

    async def fetch_actor_1h(self, event_id) -> List[Event]:
        """
        주어진 CloudTrail 이벤트의 주체(actor)를 식별하고,
        그 시점(occurred_at)부터 +1시간 동안 해당 주체가 남긴 이벤트를 반환.
        """
        actor_key, occurred_at = await self.get_actor_key_and_time(event_id)
        if not occurred_at:
            return []

        t_start = occurred_at.astimezone(timezone.utc)
        t_end = (occurred_at + timedelta(hours=1)).astimezone(timezone.utc)

        db = next(get_db())
        try:
            out: List[Event] = []
            q = (
                select(CloudTrailModel)
                .where(CloudTrailModel.event_time >= t_start)
                .where(CloudTrailModel.event_time <= t_end)
            )
            rows = db.execute(q).scalars().all()

            for ct in rows:
                ak = self._build_actor_key(
                    getattr(ct, 'user_identity', None),
                    getattr(ct, 'request_parameters', None),
                )
                # actor_key가 식별된 경우에만 필터링(없으면 전체 반환할 수도 있지만 명확성을 위해 계속 필터)
                if actor_key is not None and ak != actor_key:
                    continue

                ev = db.get(EventModel, ct.id)
                if not ev or ev.group_id != self.group_id:
                    continue

                out.append(
                    Event(
                        id=ev.id,
                        group_id=ev.group_id,
                        source_product=ev.source_product,
                        source_ip=ev.source_ip,
                        user_agent=ev.user_agent,
                        created_at=ev.created_at,
                    )
                )
            return out
        finally:
            db.close()