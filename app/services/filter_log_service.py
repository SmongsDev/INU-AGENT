from typing import List, Dict
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import FilterLog
from uuid import UUID
import logging

logger = logging.getLogger(__name__)

class FilterLogService:
    """필터 로그 저장 서비스"""
    
    def __init__(self):
        pass
    
    def save_filter_results(self, filter_results: List[Dict]) -> Dict[str, int]:
        """
        필터링 결과를 filter_log 테이블에 저장
        
        Args:
            filter_results: 필터링 결과 리스트
            [{'ml_log_id': str, 'filter_result': dict}, ...]
            
        Returns:
            저장 통계 {'success': int, 'failed': int}
        """
        if not filter_results:
            return {'success': 0, 'failed': 0}
        
        success_count = 0
        failed_count = 0
        
        try:
            db = next(get_db())
            
            try:
                for result in filter_results:
                    try:
                        ml_log_id = result.get('ml_log_id')
                        filter_data = result.get('filter_result', {})
                        threat = result.get('is_threat', False)
                        
                        if not ml_log_id:
                            failed_count += 1
                            continue
                        
                        # UUID 문자열을 UUID 객체로 변환
                        if isinstance(ml_log_id, str):
                            try:
                                ml_log_uuid = UUID(ml_log_id)
                            except ValueError:
                                logger.error(f"잘못된 UUID 형식: {ml_log_id}")
                                failed_count += 1
                                continue
                        else:
                            ml_log_uuid = ml_log_id
                        
                        # FilterLog 레코드 생성
                        filter_log = FilterLog(
                            id=ml_log_uuid,  # ml_log.id와 동일
                            result=filter_data,  # JSONB 필드에 필터링 결과 저장
                            is_threat=threat
                        )
                        
                        # 기존 레코드가 있는지 확인하고 업데이트 또는 삽입
                        existing = db.query(FilterLog).filter(FilterLog.id == ml_log_uuid).first()
                        if existing:
                            existing.result = filter_data
                            existing.is_threat = threat
                            logger.debug(f"필터 로그 업데이트: {ml_log_id}")
                        else:
                            db.add(filter_log)
                            logger.debug(f"새 필터 로그 생성: {ml_log_id}")
                        
                        success_count += 1
                        
                    except Exception as e:
                        logger.error(f"필터 로그 개별 저장 실패: {e}")
                        failed_count += 1
                        continue
                
                # 커밋
                db.commit()
                logger.info(f"✅ 필터 로그 저장 완료: {success_count}개 성공, {failed_count}개 실패")
                
            except Exception as e:
                db.rollback()
                logger.error(f"❌ 필터 로그 배치 저장 실패: {e}")
                failed_count = len(filter_results)
                success_count = 0
            
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"❌ 필터 로그 서비스 오류: {e}")
            return {'success': 0, 'failed': len(filter_results)}
        
        return {'success': success_count, 'failed': failed_count}