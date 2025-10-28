import sys
import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Any

# ML 분석 모듈 import
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ml"))
from agent.main_agent import agent
from ml.src.analysis.predict_threats_optimized import OptimizedCloudTrailPredictor
from ml.src.data.ml_result_saver import MLResultSaver
from app.services.tier1.filter import Tier1Filter
from app.services.agent_state_builder import build_supervisor_state
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class MLAnalysisService:
    """ML 분석 서비스 클래스"""

    def __init__(self, model_path: str = None, group_id: str = None):
        if model_path is None:
            model_path = str(Path(__file__).parent.parent.parent / "ml" / "models" / "cloudTrail_v2.pkl")
        self.model_path = model_path
        self.group_id = group_id
        self.predictor = None
        self.result_saver = None
        self.tier1_filter = Tier1Filter(group_id=group_id)
    
    def _initialize_components(self):
        """ML 컴포넌트들을 초기화"""
        if self.predictor is None:
            if not Path(self.model_path).exists():
                raise FileNotFoundError(f"모델 파일이 없습니다: {self.model_path}")
            self.predictor = OptimizedCloudTrailPredictor(str(self.model_path))
        
        if self.result_saver is None:
            self.result_saver = MLResultSaver()
    
    async def analyze_events(self, events_list: List[Dict[str, Any]]) -> dict:
        """
        이벤트 리스트를 ML로 분석하고 결과에 따라 자동으로 분기 처리 (비동기)

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

            # ML 분석 수행 (동기 함수를 별도 스레드에서 실행)
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                self.predictor.predict_batch_optimized,
                ml_events,
                True  # show_progress
            )

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
                    event_id = event_dict.get('id', '')

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
                    }

                    if is_threat:
                        threat_events.append(analysis_result)
                    else:
                        normal_events.append(analysis_result)

                # ML 결과를 ml_log 테이블에 저장 (비동기 실행)
                if ml_log_data:
                    save_stats = await loop.run_in_executor(
                        None,
                        self.result_saver.save_batch_results,
                        ml_log_data
                    )
                    logger.info(f"ML 결과 저장: {save_stats['success']}개 성공")

                # 분기 처리를 백그라운드 태스크로 실행 (await 없이)
                asyncio.create_task(self._process_analysis_results(threat_events, normal_events))

                logger.info(f"ML 분석 완료 및 백그라운드 처리 시작: {len(events_list)}개 처리, {len(threat_events)}개 위협 탐지, {len(normal_events)}개 정상")

                return {
                    "processed": len(events_list),
                    "threats": len(threat_events),
                    "normal": len(normal_events)
                }

            return {"processed": 0, "threats": 0, "normal": 0}

        except Exception as e:
            logger.error(f"ML 분석 오류: {e}")
            return {"processed": 0, "threats": 0, "normal": 0, "error": str(e)}
    
    def _run_agent_sync(self, event: dict, state: dict) -> dict:
        """agent() 함수를 동기적으로 실행 (별도 스레드에서 호출용)

        Args:
            event: 이벤트 데이터
            state: supervisor state

        Returns:
            agent() 함수의 결과 (report_data 또는 None)
        """
        try:
            result = agent(event, state, self.group_id)
            return result
        except Exception as e:
            logger.error(f"Agent 실행 오류: {e}", exc_info=True)
            return None

    async def _process_single_threat_event(self, threat_result: dict, state: dict) -> None:
        """단일 위협 이벤트를 agent() 함수로 전달 (비동기)

        Args:
            threat_result: 위협 이벤트 결과 딕셔너리
            state: 미리 생성된 supervisor state
        """
        try:
            # 이벤트 데이터와 ML 분석 결과 추출
            event_dict = threat_result.get('event_dict')
            ml_prediction = threat_result.get('ml_prediction', {})
            confidence = ml_prediction.get('confidence', 0.0)
            event_id = event_dict.get('id', 'Unknown')

            # agent() 함수를 별도 스레드에서 실행
            # (Analyze_agent + Supervisor_agent를 통합 실행)
            loop = asyncio.get_event_loop()
            report_data = await loop.run_in_executor(
                None,
                self._run_agent_sync,
                event_dict,
                state
            )

            if report_data:
                logger.info(f"Agent 분석 완료: Event {event_id} - 신뢰도: {confidence:.2f}, Severity: {report_data.get('severity')}")
            else:
                logger.info(f"Agent 분석 완료 (오탐 판정): Event {event_id} - 신뢰도: {confidence:.2f}")

        except Exception as e:
            logger.error(f"Agent 분석 오류: {e}", exc_info=True)

    async def _process_analysis_results(self, threat_events: List[dict], normal_events: List[dict]):
        """ML 분석 결과에 따른 분기 처리 (비동기)

        각 이벤트에 대해 state를 미리 생성한 후 해당 경로로 전달
        """

        # 1. ML 위협 탐지 이벤트들 → Supervisor Agent로 병렬 전달
        if threat_events:
            logger.info(f"ML 위협 탐지: {len(threat_events)}개 이벤트 → Supervisor Agent로 병렬 전달")

            threat_tasks = []
            for threat_result in threat_events:
                state = build_supervisor_state(group_id=self.group_id)

                threat_tasks.append(self._process_single_threat_event(threat_result, state))

            await asyncio.gather(*threat_tasks, return_exceptions=True)

        # 2. ML 정상 판단 이벤트들 → filter_log에 저장
        if normal_events:
            # (Tier1 필터에서 재검증이 필요한 경우를 위해)
            state = build_supervisor_state(group_id=self.group_id)

            normal_events_with_state = []
            for normal_result in normal_events:
                normal_result['state'] = state
                normal_events_with_state.append(normal_result)

            if self.tier1_filter:
                logger.info(f"Tier1 필터 처리: ML 정상 판단 {len(normal_events_with_state)}개 이벤트")
                await self.tier1_filter.process_ml_analysis_results(normal_events_with_state)
    
    
    def _prepare_db_results(self, ml_events: List[dict], results: List[dict]) -> tuple:
        """ML 결과를 DB 저장용 형태로 변환"""
        db_results = []
        threat_count = 0
        
        for ml_event, prediction in zip(ml_events, results):
            if prediction.get('error'):
                continue

            event_id = ml_event.get('id')
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