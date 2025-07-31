import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional, List
from pathlib import Path

from app.core.logger import get_logger
from langgraph_flow.nodes.rag.supabase_client import get_supabase_client
from app.schemas.cloudtrail import CloudTrailEvent

logger = get_logger(__name__)

class DataSyncService:
    LAST_SYNC_FILE = "last_sync_time.json"
    
    def __init__(self):
        self.supabase = get_supabase_client()
        self.last_sync_time: Optional[datetime] = None
        self._load_last_sync_time()
        
    def _get_utc_now(self) -> datetime:
        """현재 시간을 UTC로 반환합니다."""
        return datetime.now(timezone.utc)
        
    def _load_last_sync_time(self):
        """파일에서 마지막 동기화 시간을 로드합니다."""
        try:
            if os.path.exists(self.LAST_SYNC_FILE):
                with open(self.LAST_SYNC_FILE, 'r') as f:
                    data = json.load(f)
                    last_sync_str = data.get('last_sync_time')
                    if last_sync_str:
                        self.last_sync_time = datetime.fromisoformat(last_sync_str)
                        logger.info(f"마지막 동기화 시간을 파일에서 로드: {self.last_sync_time}")
        except Exception as e:
            logger.error(f"마지막 동기화 시간 로드 중 오류 발생: {str(e)}")
            
    def _save_last_sync_time(self):
        """현재 동기화 시간을 파일에 저장합니다."""
        try:
            if self.last_sync_time:
                with open(self.LAST_SYNC_FILE, 'w') as f:
                    json.dump({
                        'last_sync_time': self.last_sync_time.isoformat()
                    }, f)
                logger.info(f"마지막 동기화 시간을 파일에 저장: {self.last_sync_time}")
        except Exception as e:
            logger.error(f"마지막 동기화 시간 저장 중 오류 발생: {str(e)}")
        
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
                utc_time = self.last_sync_time.astimezone(timezone.utc)
                logger.info(f"마지막 동기화 시간 (UTC): {utc_time.isoformat()}")
                query = query.gte("created_at", utc_time.isoformat())
            else:
                logger.info("첫 번째 동기화 실행")
                
            response = query.execute()
            
            logger.info(f"쿼리 응답: {response.data if len(response.data) < 3 else f'{len(response.data)}개의 레코드'}")
            
            if response.data:
                logger.info(f"{len(response.data)}개의 새로운 CloudTrail 이벤트를 가져왔습니다.")
                
            # Supabase 응답을 CloudTrailEvent 모델로 변환
            try:
                events = [CloudTrailEvent(**event_data) for event_data in response.data]
            except Exception as e:
                logger.error(f"이벤트 변환 중 오류 발생: {str(e)}")
                logger.error(f"문제가 된 데이터: {response.data[:1] if response.data else '데이터 없음'}")
                return []
            
            # 새로운 동기화 시간 저장
            self.last_sync_time = self._get_utc_now()
            self._save_last_sync_time()
            
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
        logger.info(f"CloudTrail 이벤트 동기화 시작 (테이블: {table_name}, 주기: {interval_minutes}분)")
        
        while True:
            current_time_utc = self._get_utc_now()
            logger.info(f"새로운 이벤트 확인 중... (현재 시간 UTC: {current_time_utc.isoformat()})")
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
            else:
                logger.info("새로운 이벤트가 없습니다.")
                
            await asyncio.sleep(interval_minutes * 60)  # 분을 초로 변환