import asyncio
from datetime import datetime, timezone
from typing import List
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy import select

from app.schemas.events import Event
from app.db.session import get_db
from app.db.models import Event as EventModel
from app.services.metadata_service import MetadataService

class EventService:
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
        
    async def fetch_new_events(self) -> List[Event]:
        try:
            db = next(get_db())
            try:
                last_sync_time = self.metadata_service.get_last_sync_time(self.group_id)
                query = select(EventModel).where(EventModel.group_id == self.group_id)
                
                if last_sync_time:
                    utc_time = last_sync_time.astimezone(timezone.utc)
                    query = query.where(EventModel.created_at >= utc_time)
                    
                result = db.execute(query)
                records = result.scalars().all()
                
                try:
                    events = []
                    for record in records:
                        event_data = {
                            'id': record.id,
                            'group_id': record.group_id,
                            'source_product': record.source_product,
                            'source_ip': record.source_ip,
                            'user_agent': record.user_agent,
                            'created_at': record.created_at
                        }
                        events.append(Event(**event_data))
                except Exception:
                    return []
                
                current_time = datetime.now(timezone.utc)
                self.metadata_service.update_sync_time(self.group_id, current_time)
                
                return events
                
            finally:
                db.close()
                
        except Exception:
            return []