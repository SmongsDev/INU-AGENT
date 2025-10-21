import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy import select

from app.schemas.events import Event
from app.schemas.base import SourceProduct
from app.db.session import get_db
from app.db.models import Event as EventModel, CloudTrail as CloudTrailModel, CloudWatch as CloudWatchModel
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
        
    async def fetch_new_events(self) -> List[Dict[str, Any]]:
        try:
            db = next(get_db())
            try:
                last_sync_time = self.metadata_service.get_last_sync_time(self.group_id)
                # last_sync_time = datetime(2025, 8, 13, tzinfo=timezone.utc) # 테스트용
                
                start_time = datetime.now()
                events_dict = []
                
                # source_product별 테이블 매핑
                source_models = {
                    SourceProduct.cloudtrail: CloudTrailModel,
                    SourceProduct.cloudwatch: CloudWatchModel,
                    # 추후 SourceProduct.guardduty: GuardDutyModel 추가 가능
                }
                
                # 각 SourceProduct별로 JOIN 쿼리 실행
                for source_product, source_model in source_models.items():
                    # JOIN을 사용하여 Events와 해당 Source 테이블을 한번에 조회
                    query = (
                        select(EventModel, source_model)
                        .join(source_model, EventModel.id == source_model.id)
                        .where(EventModel.group_id == self.group_id)
                        .where(EventModel.source_product == source_product)
                    )
                    
                    if last_sync_time:
                        # DB에서 가져온 시간을 UTC로 명시적으로 처리
                        if last_sync_time.tzinfo is None:
                            utc_time = last_sync_time.replace(tzinfo=timezone.utc)
                        else:
                            utc_time = last_sync_time.astimezone(timezone.utc)
                        query = query.where(EventModel.created_at >= utc_time)
                    
                    result = db.execute(query)
                    for event_record, source_record in result:
                        event_dict = self._convert_to_standard_dict(source_record, source_product)
                        if event_dict:
                            events_dict.append(event_dict)
                
                total_query_time = (datetime.now() - start_time).total_seconds()
                print(f"[DEBUG] Optimized DB Query Time: {total_query_time:.3f}s")
                
                current_time = datetime.now(timezone.utc)
                self.metadata_service.update_sync_time(self.group_id, current_time)
                
                return events_dict
                
            finally:
                db.close()
                
        except Exception:
            return []
    
    def _convert_to_standard_dict(self, source_record, source_product: SourceProduct) -> Dict[str, Any]:
        """소스 레코드를 표준화된 딕셔너리로 변환"""
        try:
            base_dict = {
                '_event_id': str(source_record.id),
                '_source_product': source_product.value,
                'created_at': source_record.event_time.isoformat() if hasattr(source_record, 'event_time') and source_record.event_time else '',
                'updated_at': None,
            }
            
            if source_product == SourceProduct.cloudtrail:
                # CloudTrail 특화 필드 매핑
                base_dict.update({
                    'event_name': getattr(source_record, 'event_name', ''),
                    'event_source': getattr(source_record, 'event_source', ''),
                    'source_ip': str(getattr(source_record, 'source_ip', '')),
                    'user_agent': getattr(source_record, 'user_agent', ''),
                    'event_time': source_record.event_time.isoformat() if hasattr(source_record, 'event_time') and source_record.event_time else '',
                    'event_id': str(getattr(source_record, 'event_id', '')),
                    'event_version': getattr(source_record, 'event_version', ''),
                    'event_category': getattr(source_record, 'event_category', ''),
                    'event_type': getattr(source_record, 'event_type', ''),
                    'aws_region': getattr(source_record, 'aws_region', ''),
                    'read_only': getattr(source_record, 'read_only', None),
                    'management_event': getattr(source_record, 'management_event', None),
                    'error_code': getattr(source_record, 'error_code', ''),
                    'error_message': getattr(source_record, 'error_message', ''),
                    'user_identity': getattr(source_record, 'user_identity', {}),
                    'user_identity_type': getattr(source_record, 'user_identity_type', ''),
                    'user_identity_arn': getattr(source_record, 'user_identity_arn', ''),
                    'request_parameters': getattr(source_record, 'request_parameters', None),
                    'response_elements': getattr(source_record, 'response_elements', None),
                })
                
            elif source_product == SourceProduct.cloudwatch:
                # CloudWatch 특화 필드 매핑
                base_dict.update({
                    'event_name': getattr(source_record, 'event_name', ''),
                    'event_source': 'cloudwatch',
                    'source_ip': str(source_record.source_ip) if getattr(source_record, 'source_ip', None) else '',
                    'user_agent': getattr(source_record, 'user_agent', ''),
                    'event_time': source_record.event_time.isoformat() if source_record.event_time else base_dict['created_at'],
                    # CloudWatch 특화 필드들 추가 가능
                })
            
            return base_dict
            
        except Exception as e:
            print(f"[ERROR] Failed to convert record: {str(e)}")
            return None