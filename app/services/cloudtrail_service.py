import asyncio
from datetime import datetime, timezone
from typing import List
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy import select

from app.schemas.cloudtrail import CloudTrailEvent
from app.db.session import get_db
from app.db.models import CloudTrail
from app.services.metadata_service import MetadataService

class CloudTrailService:
    def __init__(self, group_id: PgUUID):
        self.group_id = group_id
        self.metadata_service = None
        self._init_metadata_service()
        
    def _init_metadata_service(self):
        try:
            db = next(get_db())
            self.metadata_service = MetadataService(db)
        except Exception:
            raise
        
    def _get_utc_now(self) -> datetime:
        return datetime.now(timezone.utc)
        
    async def fetch_new_events(self) -> List[CloudTrailEvent]:
        try:
            db = next(get_db())
            try:
                last_sync_time = self.metadata_service.get_last_sync_time(self.group_id)
                query = select(CloudTrail).where(CloudTrail.group_id == self.group_id)
                
                if last_sync_time:
                    utc_time = last_sync_time.astimezone(timezone.utc)
                    query = query.where(CloudTrail.created_at >= utc_time)
                    
                result = db.execute(query)
                records = result.scalars().all()
                
                try:
                    events = []
                    for record in records:
                        event_data = {
                            'event_id': record.event_id,
                            'event_version': record.event_version,
                            'event_time': record.event_time.isoformat() if record.event_time else None,
                            'event_source': record.event_source,
                            'event_name': record.event_name,
                            'aws_region': record.aws_region,
                            'source_ip': str(record.source_ip) if record.source_ip else None,
                            'user_agent': record.user_agent,
                            'error_code': record.error_code,
                            'error_message': record.error_message,
                            'request_parameters': record.request_parameters,
                            'response_elements': record.response_elements,
                            'user_identity': record.user_identity,
                            'resources': record.resources,
                            'event_category': record.event_category,
                            'event_type': record.event_type,
                            'management_event': record.management_event,
                            'recipient_account_id': record.recipient_account_id,
                            'shared_event_id': record.shared_event_id,
                            'tls_details': record.tls_details,
                            'insight_details': record.insight_details
                        }
                        events.append(CloudTrailEvent(**event_data))
                except Exception:
                    return []
                
                current_time = self._get_utc_now()
                self.metadata_service.update_sync_time(self.group_id, current_time)
                
                return events
                
            finally:
                db.close()
                
        except Exception:
            return []
            
    async def start_monitoring(self, interval_minutes: int = 5):
        while True:
            await self.fetch_new_events()
            await asyncio.sleep(interval_minutes * 60)