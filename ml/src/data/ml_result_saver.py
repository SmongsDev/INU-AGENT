import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from uuid import UUID
from dotenv import load_dotenv
import logging
from contextlib import contextmanager

# 로거 설정
logger = logging.getLogger(__name__)

# 프로젝트 루트 디렉토리를 Python path에 추가
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from app.db.models import MLLog, Event
from app.db.session import get_db


class MLResultSaver:
    """
    ML 분석 결과를 데이터베이스의 ml_log 테이블에 저장하는 클래스
    """
    
    def __init__(self, db_session: Optional[Session] = None):
        """
        ML 결과 저장기를 초기화합니다.
        
        Args:
            db_session: 데이터베이스 세션 (None이면 새로 생성)
        """
        self.db_session = db_session
        self._session_created = db_session is None
    
    def _get_session(self) -> Session:
        """데이터베이스 세션을 반환합니다."""
        if self.db_session is None:
            return next(get_db())
        return self.db_session
    
    def save_single_result(self, 
                          event_id: str,
                          severity: int,
                          confidence: float,
                          result_data: Dict[str, Any]) -> bool:
        """
        단일 ML 분석 결과를 저장합니다.
        
        Args:
            event_id: 이벤트 ID (events 테이블의 id)
            severity: ML 분석 결과 심각도 (0: 정상, 1: 위협)
            confidence: ML 분석 결과 신뢰도 (0.0-1.0)
            result_data: ML 분석 상세 결과 데이터
            
        Returns:
            저장 성공 여부
        """
        session = self._get_session()
        
        try:
            # 이벤트 존재 확인
            event = session.query(Event).filter(Event.id == UUID(event_id)).first()
            if not event:
                print(f"❌ 이벤트를 찾을 수 없습니다: {event_id}")
                return False
            
            # 기존 ML 로그가 있는지 확인
            existing_ml_log = session.query(MLLog).filter(MLLog.id == UUID(event_id)).first()
            
            if existing_ml_log:
                # 기존 결과 업데이트
                existing_ml_log.severity = severity
                existing_ml_log.confidence = confidence
                print(f"✅ ML 로그 업데이트됨: {event_id}")
            else:
                # 새 ML 로그 생성
                ml_log = MLLog(
                    id=UUID(event_id),
                    event_id=UUID(event_id),
                    severity=severity,
                    confidence=confidence
                )
                session.add(ml_log)
                print(f"✅ 새 ML 로그 생성됨: {event_id}")
            
            session.commit()
            return True
            
        except Exception as e:
            print(f"❌ ML 결과 저장 실패 (event_id: {event_id}): {e}")
            session.rollback()
            return False
        finally:
            if self._session_created:
                session.close()
    
    def save_batch_results(self, results: List[Dict[str, Any]], batch_size: int = 1000) -> Dict[str, int]:
        """
        여러 ML 분석 결과를 배치로 저장합니다.
        
        Args:
            results: ML 결과 리스트, 각 항목은 다음 키를 포함해야 함:
                - event_id: 이벤트 ID
                - severity: 심각도
                - confidence: 신뢰도
                - result_data: 상세 결과 데이터
                
        Returns:
            저장 통계 {'success': int, 'failed': int, 'updated': int, 'created': int}
        """
        session = self._get_session()
        stats = {'success': 0, 'failed': 0, 'updated': 0, 'created': 0}
        
        try:
            # 배치 단위로 처리하여 성능 최적화
            for batch_start in range(0, len(results), batch_size):
                batch = results[batch_start:batch_start + batch_size]
                
                # 배치의 모든 event_id를 한번에 조회 (성능 최적화)
                event_ids = [UUID(result['event_id']) for result in batch]
                
                # Event 테이블에서 존재하는 이벤트들을 한번에 조회
                existing_events = session.query(Event.id).filter(Event.id.in_(event_ids)).all()
                existing_event_ids = {event.id for event in existing_events}
                
                # MLLog 테이블에서 기존 로그들을 한번에 조회
                existing_ml_logs = session.query(MLLog).filter(MLLog.id.in_(event_ids)).all()
                existing_ml_log_dict = {log.id: log for log in existing_ml_logs}
                
                # 벌크 연산을 위한 데이터 준비
                updates_data = []
                inserts_data = []
                
                for idx, result in enumerate(batch):
                    try:
                        event_id = UUID(result['event_id'])
                        severity = result['severity']
                        confidence = result['confidence']
                        result_data = result.get('result_data', {})
                        
                        # 이벤트 존재 확인 (이미 조회된 결과 사용)
                        if event_id not in existing_event_ids:
                            logger.error(f"이벤트를 찾을 수 없습니다: {event_id}")
                            stats['failed'] += 1
                            continue
                        
                        # 기존 ML 로그 확인 (이미 조회된 결과 사용)
                        if event_id in existing_ml_log_dict:
                            # 업데이트용 데이터 준비
                            updates_data.append({
                                'id': event_id,
                                'severity': severity,
                                'confidence': confidence
                            })
                            stats['updated'] += 1
                        else:
                            # 삽입용 데이터 준비
                            inserts_data.append({
                                'id': event_id,
                                'event_id': event_id,
                                'severity': severity,
                                'confidence': confidence
                            })
                            stats['created'] += 1
                        
                        stats['success'] += 1
                
                    except Exception as e:
                        logger.error(f"개별 결과 준비 실패: {e}")
                        stats['failed'] += 1
                        continue
                
                # 벌크 연산 실행
                # 업데이트는 직접 SQL로 처리 (진짜 벌크 연산)
                if updates_data:
                    # 같은 severity, confidence로 업데이트할 항목들을 그룹핑
                    update_groups = {}
                    for item in updates_data:
                        key = (item['severity'], item['confidence'])
                        if key not in update_groups:
                            update_groups[key] = []
                        update_groups[key].append(item['id'])

                    # 그룹별로 단일 UPDATE 쿼리 실행
                    from sqlalchemy import text
                    for (severity, confidence), ids in update_groups.items():
                        if ids:
                            # SQL Injection 방지: 파라미터 바인딩 사용
                            placeholders = ','.join([f':id_{i}' for i in range(len(ids))])
                            query = text(f"""
                                UPDATE ml_log
                                SET severity = :severity, confidence = :confidence
                                WHERE id::text IN ({placeholders})
                            """)
                            params = {'severity': severity, 'confidence': confidence}
                            for i, uuid_id in enumerate(ids):
                                params[f'id_{i}'] = str(uuid_id)
                            session.execute(query, params)
                
                # 벌크 삽입 (이미 효율적)
                if inserts_data:
                    session.bulk_insert_mappings(MLLog, inserts_data)
                
                # 배치마다 중간 커밋 (대용량 데이터 처리 최적화)
                if (batch_start + batch_size) % (batch_size * 5) == 0:  # 5000개마다 커밋
                    session.commit()
            
            # 최종 커밋 (남은 데이터)
            session.commit()
            
            logger.info(f"ML 결과 배치 저장 완료: {len(results)}개 처리")
            logger.info(f"성공: {stats['success']}개, 실패: {stats['failed']}개, 생성: {stats['created']}개, 업데이트: {stats['updated']}개")
            
            return stats
            
        except Exception as e:
            print(f"❌ 배치 저장 중 오류: {e}")
            session.rollback()
            return stats
        finally:
            if self._session_created:
                session.close()
    
    def convert_ml_prediction_to_severity(self, is_threat: bool, confidence: float) -> int:
        """
        ML 예측 결과를 이진 분류로 변환합니다.
        
        Args:
            is_threat: ML 모델의 위협 탐지 결과
            confidence: ML 모델의 신뢰도
            
        Returns:
            심각도 점수 (0: 정상, 1: 위협)
        """
        return 1 if is_threat else 0
    
    def prepare_result_data(self, 
                           ml_prediction: Dict[str, Any], 
                           original_event: Dict[str, Any],
                           model_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        ML 예측 결과를 result 필드에 저장할 형태로 준비합니다.
        
        Args:
            ml_prediction: ML 모델 예측 결과
            original_event: 원본 이벤트 데이터
            model_info: 모델 정보 (선택사항)
            
        Returns:
            result 필드에 저장할 데이터
        """
        result_data = {
            'prediction': ml_prediction,
            'timestamp': datetime.now().isoformat(),
            'event_summary': {
                'event_name': original_event.get('eventName'),
                'event_source': original_event.get('eventSource'),
                'event_time': original_event.get('eventTime'),
                'source_ip': original_event.get('sourceIPAddress'),
                'user_name': original_event.get('userIdentity', {}).get('userName')
            }
        }
        
        if model_info:
            result_data['model_info'] = model_info
            
        return result_data
    
    def get_ml_statistics(self, group_id: Optional[str] = None) -> Dict[str, Any]:
        """
        ML 분석 결과 통계를 반환합니다.
        
        Args:
            group_id: 특정 그룹의 통계 (None이면 전체)
            
        Returns:
            ML 분석 통계
        """
        session = self._get_session()
        
        try:
            # 기본 쿼리
            ml_query = session.query(MLLog)
            
            if group_id:
                ml_query = ml_query.join(Event, MLLog.id == Event.id).filter(Event.group_id == UUID(group_id))
            
            # 전체 통계
            total_analyzed = ml_query.count()
            
            if total_analyzed == 0:
                return {
                    'total_analyzed': 0,
                    'severity_distribution': {},
                    'confidence_stats': {},
                    'threat_count': 0,
                    'threat_percentage': 0
                }
            
            # 심각도별 분포
            severity_dist = {}
            for severity in range(2):  # 0-1 (정상, 위협)
                count = ml_query.filter(MLLog.severity == severity).count()
                severity_dist[severity] = count
            
            # 위협 통계
            threat_count = ml_query.filter(MLLog.severity == 1).count()
            threat_percentage = (threat_count / total_analyzed) * 100 if total_analyzed > 0 else 0
            
            # 신뢰도 통계 (위협으로 분류된 것만)
            threat_confidences = [ml.confidence for ml in ml_query.filter(MLLog.severity == 1).all()]
            confidence_stats = {}
            if threat_confidences:
                confidence_stats = {
                    'min': min(threat_confidences),
                    'max': max(threat_confidences),
                    'avg': sum(threat_confidences) / len(threat_confidences)
                }
            
            return {
                'total_analyzed': total_analyzed,
                'severity_distribution': severity_dist,
                'confidence_stats': confidence_stats,
                'threat_count': threat_count,
                'threat_percentage': round(threat_percentage, 2),
                'group_id': group_id
            }
            
        except Exception as e:
            print(f"❌ ML 통계 조회 중 오류: {e}")
            return {}
        finally:
            if self._session_created:
                session.close()