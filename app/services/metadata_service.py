from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import UUID as PgUUID

from app.db.models import Meta_Data

class MetadataService:
    def __init__(self, db: Session):
        self.db = db

    def get_last_sync_time(self, group_id: PgUUID) -> Optional[datetime]:
        try:
            query = select(Meta_Data).where(Meta_Data.group_id == group_id)
            result = self.db.execute(query).scalar_one_or_none()
            
            if result:
                return result.data_sync_time
            return None
            
        except Exception:
            return None

    def update_sync_time(self, group_id: PgUUID, sync_time: Optional[datetime] = None) -> bool:
        try:
            sync_time = sync_time or datetime.now(timezone.utc)
            
            metadata = self.db.execute(
                select(Meta_Data).where(Meta_Data.group_id == group_id)
            ).scalar_one_or_none()
            
            if metadata:
                metadata.data_sync_time = sync_time
            else:
                metadata = Meta_Data(
                    group_id=group_id,
                    data_sync_time=sync_time
                )
                self.db.add(metadata)
            
            self.db.commit()
            return True
            
        except Exception:
            self.db.rollback()
            return False

    def get_or_create_metadata(self, group_id: PgUUID) -> Optional[Meta_Data]:
        try:
            metadata = self.db.execute(
                select(Meta_Data).where(Meta_Data.group_id == group_id)
            ).scalar_one_or_none()
            
            if not metadata:
                metadata = Meta_Data(
                    group_id=group_id,
                    data_sync_time=datetime.now(timezone.utc)
                )
                self.db.add(metadata)
                self.db.commit()
            
            return metadata
            
        except Exception:
            self.db.rollback()
            return None

    def get_agent_flow(self, group_id: PgUUID) -> Optional[Dict[str, Any]]:
        """특정 그룹의 agent_flow JSON 데이터를 가져옵니다."""
        try:
            query = select(Meta_Data.agent_flow).where(Meta_Data.group_id == group_id)
            result = self.db.execute(query).scalar_one_or_none()
            return result
            
        except Exception:
            return None