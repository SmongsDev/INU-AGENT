import os
import sys
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv
import logging
from contextlib import contextmanager

# 로거 설정
logger = logging.getLogger(__name__)

# 프로젝트 루트 디렉토리를 Python path에 추가
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from app.db.models import Event, CloudTrail


class DatabaseDataLoader:
    """
    RDS 데이터베이스에서 CloudTrail 로그 데이터를 로드하는 클래스
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        데이터베이스 로더를 초기화합니다.
        
        Args:
            database_url: 데이터베이스 연결 URL (None이면 .env에서 로드)
        """
        load_dotenv()

        if database_url is None:
            database_url = os.getenv("TEST_DATABASE_URL")

        if not database_url:
            raise ValueError("데이터베이스 URL이 설정되지 않았습니다. 환경변수를 확인하세요.")
        
        # 연결 풀 설정으로 성능 최적화
        self.engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=20,
            max_overflow=30,
            pool_recycle=3600,
            pool_pre_ping=True,
            echo=False
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    @contextmanager
    def get_db_session(self):
        """컨텍스트 매니저로 데이터베이스 세션을 반환합니다."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def load_cloudtrail_events(self, 
                              group_id: Optional[str] = None,
                              limit: Optional[int] = None,
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None,
                              unprocessed_only: bool = False) -> List[Dict]:
        """
        CloudTrail 이벤트를 데이터베이스에서 로드합니다.
        
        Args:
            group_id: 특정 그룹의 데이터만 로드 (None이면 모든 그룹)
            limit: 최대 로드할 이벤트 수
            start_time: 시작 시간 필터
            end_time: 종료 시간 필터
            unprocessed_only: ML 분석이 안된 이벤트만 로드할지 여부
            
        Returns:
            CloudTrail 로그 이벤트 리스트 (ML 모델이 기대하는 형식)
        """
        with self.get_db_session() as session:
            try:
                # 기본 쿼리 구성
                query = session.query(Event, CloudTrail).join(CloudTrail, Event.id == CloudTrail.id)
                
                # 필터 적용
                if group_id:
                    query = query.filter(Event.group_id == group_id)
                
                if start_time:
                    query = query.filter(Event.created_at >= start_time)
                    
                if end_time:
                    query = query.filter(Event.created_at <= end_time)
                
                if unprocessed_only:
                    # ML 분석이 안된 이벤트만
                    from app.db.models import MLLog
                    processed_event_ids = session.query(MLLog.id).subquery()
                    query = query.filter(~Event.id.in_(processed_event_ids))
                
                # 제한 및 정렬 적용
                query = query.order_by(Event.created_at.desc())
                if limit:
                    query = query.limit(limit)
                
                results = query.all()
                
                logger.info(f"데이터베이스에서 {len(results)}개의 CloudTrail 이벤트를 로드했습니다.")
                
                # ML 모델 형식으로 변환
                formatted_events = []
                for event, cloudtrail in results:
                    formatted_event = self._format_cloudtrail_event(event, cloudtrail)
                    if formatted_event:
                        formatted_events.append(formatted_event)
                
                return formatted_events
                
            except Exception as e:
                logger.error(f"CloudTrail 이벤트 로드 중 오류: {e}")
                return []
    
    def _format_cloudtrail_event(self, event: Event, cloudtrail: CloudTrail) -> Dict:
        """
        데이터베이스의 CloudTrail 이벤트를 ML 모델이 기대하는 형식으로 변환합니다.
        """
        try:
            formatted_event = {
                # 기본 필드 (camelCase + snake_case 호환)
                'eventVersion': cloudtrail.event_version,
                'event_version': cloudtrail.event_version,
                'eventTime': cloudtrail.event_time.isoformat() if cloudtrail.event_time else event.created_at.isoformat(),
                'event_time': cloudtrail.event_time.isoformat() if cloudtrail.event_time else event.created_at.isoformat(),
                'eventSource': cloudtrail.event_source,
                'event_source': cloudtrail.event_source,
                'eventName': cloudtrail.event_name,
                'event_name': cloudtrail.event_name,
                'awsRegion': cloudtrail.aws_region,
                'aws_region': cloudtrail.aws_region,
                'sourceIPAddress': str(cloudtrail.source_ip) if cloudtrail.source_ip else str(event.source_ip),
                'source_ip': str(cloudtrail.source_ip) if cloudtrail.source_ip else str(event.source_ip),
                'userAgent': cloudtrail.user_agent or event.user_agent,
                'user_agent': cloudtrail.user_agent or event.user_agent,
                'readOnly': cloudtrail.read_only,
                'read_only': cloudtrail.read_only,
                'managementEvent': cloudtrail.management_event,
                'management_event': cloudtrail.management_event,

                # JSON 필드들 (camelCase + snake_case 호환)
                'userIdentity': cloudtrail.user_identity or {},
                'user_identity': cloudtrail.user_identity or {},
                'requestParameters': cloudtrail.request_parameters or {},
                'request_parameters': cloudtrail.request_parameters or {},
                'responseElements': cloudtrail.response_elements or {},
                'response_elements': cloudtrail.response_elements or {},
                'resources': cloudtrail.resources or [],

                # 오류 정보 (camelCase + snake_case 호환)
                'errorCode': cloudtrail.error_code,
                'error_code': cloudtrail.error_code,
                'errorMessage': cloudtrail.error_message,
                'error_message': cloudtrail.error_message,

                # 추가 메타데이터
                'id': str(event.id),  # ML 결과 저장시 사용
                '_group_id': str(event.group_id)
            }

            return formatted_event

        except Exception as e:
            logger.error(f"CloudTrail 이벤트 포맷팅 오류: {e}")
            return None
    
    def get_event_statistics(self, group_id: Optional[str] = None) -> Dict:
        """
        이벤트 통계를 반환합니다.
        
        Args:
            group_id: 특정 그룹의 통계 (None이면 전체)
            
        Returns:
            통계 정보 딕셔너리
        """
        with self.get_db_session() as session:
            try:
                # 기본 쿼리
                event_query = session.query(Event)
                cloudtrail_query = session.query(Event).join(CloudTrail, Event.id == CloudTrail.id)
                
                if group_id:
                    event_query = event_query.filter(Event.group_id == group_id)
                    cloudtrail_query = cloudtrail_query.filter(Event.group_id == group_id)
                
                # 통계 수집
                total_events = event_query.count()
                cloudtrail_count = cloudtrail_query.count()
                
                # ML 처리된 이벤트 수
                from app.db.models import MLLog
                ml_query = session.query(MLLog)
                if group_id:
                    ml_query = ml_query.join(Event, MLLog.id == Event.id).filter(Event.group_id == group_id)
                processed_count = ml_query.count()
                
                # 시간 범위
                time_range = {}
                if total_events > 0:
                    earliest = event_query.order_by(Event.created_at.asc()).first()
                    latest = event_query.order_by(Event.created_at.desc()).first()
                    time_range = {
                        'earliest': earliest.created_at.isoformat() if earliest else None,
                        'latest': latest.created_at.isoformat() if latest else None
                    }
                
                return {
                    'total_events': total_events,
                    'cloudtrail_events': cloudtrail_count,
                    'ml_processed_events': processed_count,
                    'unprocessed_events': total_events - processed_count,
                    'time_range': time_range,
                    'group_id': group_id
                }
                
            except Exception as e:
                logger.error(f"통계 조회 중 오류: {e}")
                return {}
    
    def validate_connection(self) -> bool:
        """데이터베이스 연결을 확인합니다."""
        try:
            with self.get_db_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"데이터베이스 연결 실패: {e}")
            return False