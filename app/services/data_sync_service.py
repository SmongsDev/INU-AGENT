import asyncio
from datetime import datetime, timedelta
from typing import Optional, List

from app.core.logger import get_logger
from agents.rag.supabase_client import get_supabase_client
from app.schemas.cloudtrail import CloudTrailEvent

logger = get_logger(__name__)

class DataSyncService:
    def __init__(self):
        self.supabase = get_supabase_client()
        self.last_sync_time: Optional[datetime] = None
        
    async def fetch_new_data(self, table_name: str) -> List[CloudTrailEvent]:
        """
        주어진 테이블에서 마지막 동기화 시간 이후의 새로운 CloudTrail 이벤트를 가져옵니다.
        
        Args:
            table_name (str): 데이터를 가져올 테이블 이름
            
        Returns:
            List[CloudTrailEvent]: 새로운 CloudTrail 이벤트 목록
        """
        try:
            query = self.supabase.table(table_name).select("*")
            
            if self.last_sync_time:
                query = query.gte("created_at", self.last_sync_time.isoformat())
                
            response = query.execute()
            
            if response.data:
                logger.info(f"{len(response.data)}개의 새로운 CloudTrail 이벤트를 가져왔습니다.")
                
            # Supabase 응답을 CloudTrailEvent 모델로 변환
            events = [CloudTrailEvent(**event_data) for event_data in response.data]
            
            self.last_sync_time = datetime.now()
            return events
            
        except Exception as e:
            logger.error(f"데이터 동기화 중 오류 발생: {str(e)}")
            return []
            
    async def start_sync(self, table_name: str, interval_minutes: int = 5):
        """
        주기적으로 새로운 CloudTrail 이벤트를 동기화합니다.
        
        Args:
            table_name (str): 동기화할 테이블 이름
            interval_minutes (int): 동기화 주기 (분 단위)
        """
        while True:
            new_events = await self.fetch_new_data(table_name)
            
            if new_events:
                for event in new_events:
                    log_message = (
                        f"새로운 CloudTrail 이벤트 처리:\n"
                        f"  - Event ID: {event.event_id}\n"
                        f"  - Source: {event.event_source}\n"
                        f"  - Name: {event.event_name}\n"
                        f"  - Region: {event.aws_region}\n"
                        f"  - Time: {event.event_time}\n"
                    )
                    
                    if event.error_code:
                        log_message += f"  - Error: {event.error_code} - {event.error_message}\n"
                        
                    logger.info(log_message)
                    # 여기에 이벤트 처리 로직을 추가할 수 있습니다.
                
            await asyncio.sleep(interval_minutes * 60)  # 분을 초로 변환 