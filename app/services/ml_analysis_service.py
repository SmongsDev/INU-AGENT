import sys
import logging
from pathlib import Path
from typing import List, Dict, Any

# ML 분석 모듈 import
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml"))
from ml.src.analysis.predict_threats_optimized import OptimizedCloudTrailPredictor
from ml.src.data.ml_result_saver import MLResultSaver
from agent.graph import process_security_event
from app.services.tier1.filter import Tier1Filter
from datetime import datetime

logger = logging.getLogger(__name__)

class MLAnalysisService:
    """ML 분석 서비스 클래스"""
    
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = str(Path(__file__).parent.parent.parent / "ml" / "models" / "cloudTrail_v1.pkl")
        self.model_path = model_path
        self.predictor = None
        self.result_saver = None
        self.tier1_filter = Tier1Filter()
    
    def _initialize_components(self):
        """ML 컴포넌트들을 초기화"""
        if self.predictor is None:
            if not Path(self.model_path).exists():
                raise FileNotFoundError(f"모델 파일이 없습니다: {self.model_path}")
            self.predictor = OptimizedCloudTrailPredictor(str(self.model_path))
        
        if self.result_saver is None:
            self.result_saver = MLResultSaver()
    
    def analyze_events(self, events_list: List[Dict[str, Any]]) -> dict:
        """
        이벤트 리스트를 ML로 분석하고 결과에 따라 자동으로 분기 처리
        
        Args:
            events_list: 표준화된 이벤트 딕셔너리들의 리스트
            
        Returns:
            처리 통계 딕셔너리
        """
        if not events_list:
            return {"processed": 0, "threats": 0, "normal": 0}
        
        try:
            logger.info(f"ML 위협 분석 시작: {len(events_list)}개 이벤트")
            
            # ML 컴포넌트 초기화
            self._initialize_components()
            
            # 이미 표준화된 딕셔너리이므로 변환 없이 바로 사용
            ml_events = events_list
            
            # ML 분석 수행
            results = self.predictor.predict_batch_optimized(ml_events, show_progress=True)
            
            if results:
                # ML 결과를 ml_log 테이블에 저장
                ml_log_data = []
                threat_events = []
                normal_events = []
                
                for event_dict, ml_event, prediction in zip(events_list, ml_events, results):
                    if prediction.get('error'):
                        continue
                    
                    is_threat = prediction.get('is_threat', False)
                    confidence = prediction.get('confidence', 0.0)
                    event_id = event_dict.get('_event_id', '')
                    
                    # ml_log 테이블 저장용 데이터
                    ml_log_data.append({
                        'event_id': event_id,
                        'severity': 1 if is_threat else 0,  # 0: 정상, 1: 위협
                        'confidence': confidence,
                        'result_data': {}
                    })
                    
                    # 분기 처리용 결과 구조 - 딕셔너리로 유지 (필요시에만 변환)
                    analysis_result = {
                        'event_dict': event_dict,  # 딕셔너리 그대로 저장
                        'ml_prediction': {
                            'is_threat': is_threat,
                            'confidence': confidence,
                            'prediction_details': prediction
                        },
                        'ml_event_data': ml_event,
                        'is_threat': is_threat
                    }
                    
                    if is_threat:
                        threat_events.append(analysis_result)
                    else:
                        normal_events.append(analysis_result)
                
                # ML 결과를 ml_log 테이블에 저장
                if ml_log_data:
                    save_stats = self.result_saver.save_batch_results(ml_log_data)
                    logger.info(f"ML 결과 저장: {save_stats['success']}개 성공")
                
                # 분기 처리 수행
                self._process_analysis_results(threat_events, normal_events)
                
                logger.info(f"ML 분석 및 분기 처리 완료: {len(events_list)}개 처리, {len(threat_events)}개 위협 탐지, {len(normal_events)}개 정상")
                
                return {
                    "processed": len(events_list),
                    "threats": len(threat_events),
                    "normal": len(normal_events)
                }
            
            return {"processed": 0, "threats": 0, "normal": 0}
            
        except Exception as e:
            logger.error(f"ML 분석 오류: {e}")
            return {"processed": 0, "threats": 0, "normal": 0, "error": str(e)}
    
    def _process_analysis_results(self, threat_events: List[dict], normal_events: List[dict]):
        """ML 분석 결과에 따른 분기 처리"""

        # 1. ML 위협 탐지 이벤트들 → filter_log에 저장
        if threat_events:
            # 다시 되돌릴 예정
            logger.info(f"ML 위협 탐지: {len(threat_events)}개 이벤트 → filter_log 테이블에 저장")
            self._save_threat_events_to_filter_log(threat_events)

            # 기존 Tier2 Agent 로직 주석 처리
            # for threat_result in threat_events:
            #     try:
            #         # 딕셔너리를 직접 Agent에 전달 (변환 불필요)
            #         event_dict = threat_result.get('event_dict')
            #         confidence = threat_result.get('ml_prediction', {}).get('confidence', 0.0)
            #
            #         # 딕셔너리를 직접 Agent에 전달
            #         agent_result = process_security_event(event_dict, confidence)
            #         logger.info(f"Agent 분석 완료: Event {event_dict.get('_event_id')} - 오탐여부: {agent_result['is_false_positive']}")
            #
            #     except Exception as e:
            #         logger.error(f"Tier2 Agent 분석 오류: {e}")

        # 2. ML 정상 판단 이벤트들 → filter_log에 저장
        if normal_events:
            # 기존 Tier1 필터 로직 주석 처리
            if self.tier1_filter:
                logger.info(f"Tier1 필터 처리: ML 정상 판단 {len(normal_events)}개 이벤트")
                self.tier1_filter.process_ml_analysis_results(normal_events)
    
    
    def _prepare_db_results(self, ml_events: List[dict], results: List[dict]) -> tuple:
        """ML 결과를 DB 저장용 형태로 변환"""
        db_results = []
        threat_count = 0
        
        for ml_event, prediction in zip(ml_events, results):
            if prediction.get('error'):
                continue
            
            event_id = ml_event.get('_event_id') 
            if not event_id:
                continue
            
            is_threat = prediction.get('is_threat', False)
            confidence = prediction.get('confidence', 0.0)
            
            if is_threat:
                threat_count += 1
            
            severity = self.result_saver.convert_ml_prediction_to_severity(is_threat, confidence)
            result_data = self.result_saver.prepare_result_data(prediction, ml_event)
            
            db_results.append({
                'event_id': event_id,
                'severity': severity,
                'confidence': confidence,
                'result_data': result_data
            })
        
        return db_results, threat_count

    # 다시 되돌릴 예정 (제거)
    def _save_threat_events_to_filter_log(self, threat_events: List[dict]):
        """ML이 위협으로 판단한 이벤트들을 filter_log에 저장"""
        try:
            from app.services.filter_log_service import FilterLogService
            filter_log_service = FilterLogService()

            filter_log_data = []

            for threat_result in threat_events:
                event_dict = threat_result.get('event_dict', {})
                ml_prediction = threat_result.get('ml_prediction', {})
                event_id = event_dict.get('_event_id', '')
                is_threat = threat_result.get("is_threat", '')

                filter_data = {
                    "ml_log_id": event_id,
                    "filter_result": {
                        "should_analyze": True,
                        "filter_reason": "ML 위협 탐지",
                        "risk_level": "high",
                        "ml_prediction": {
                            "is_threat": ml_prediction.get('is_threat', True),
                            "confidence": ml_prediction.get('confidence', 0.0)
                        },
                        "filter_timestamp": str(datetime.now())
                    },
                    "is_threat": is_threat
                }
                filter_log_data.append(filter_data)

            if filter_log_data:
                save_stats = filter_log_service.save_filter_results(filter_log_data)
                logger.info(f"ML 위협 이벤트 filter_log 저장: {save_stats.get('success', 0)}개 성공")

        except Exception as e:
            logger.error(f"위협 이벤트 filter_log 저장 오류: {e}")
