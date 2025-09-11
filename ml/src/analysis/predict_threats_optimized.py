#!/usr/bin/env python3
"""
최적화된 CloudTrail 위협 탐지 예측 스크립트

성능 개선 사항:
- 배치 처리를 통한 대용량 데이터 처리
- 메모리 효율적인 청크 단위 처리
- 연결 풀을 통한 데이터베이스 최적화
- 개선된 로깅 및 에러 핸들링
"""

import argparse
import sys
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional

# 프로젝트 루트를 시스템 경로에 추가
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from ml.src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
from ml.src.data.db_data_loader import DatabaseDataLoader
from ml.src.data.ml_result_saver import MLResultSaver

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OptimizedCloudTrailPredictor:
    """
    최적화된 CloudTrail 위협 예측 클래스
    배치 처리와 메모리 효율성에 중점을 둔 개선 버전
    """
    
    def __init__(self, model_path: str, batch_size: int = 5000):
        """
        최적화된 예측기를 초기화합니다.
        
        Args:
            model_path: 훈련된 모델 파일 경로
            batch_size: 배치 처리 크기
        """
        self.model_path = model_path
        self.batch_size = batch_size
        self.detector = CloudTrailThreatDetector()
        self.is_loaded = False
        self._load_model()
    
    def _load_model(self):
        """모델을 로드합니다."""
        try:
            if not Path(self.model_path).exists():
                raise FileNotFoundError(f"모델 파일이 없습니다: {self.model_path}")
            
            logger.info(f"모델 로드 중: {self.model_path}")
            self.detector.load_model(self.model_path)
            self.is_loaded = True
            logger.info("✅ 모델 로드 완료")
            
        except Exception as e:
            logger.error(f"❌ 모델 로드 실패: {e}")
            raise
    
    def predict_batch_optimized(self, 
                               log_events: List[Dict], 
                               show_progress: bool = True) -> List[Dict]:
        """
        최적화된 배치 예측을 수행합니다.
        
        Args:
            log_events: CloudTrail 로그 이벤트 리스트
            show_progress: 진행 상황 표시 여부
            
        Returns:
            예측 결과 리스트
        """
        if not self.is_loaded:
            raise ValueError("모델이 로드되지 않았습니다")
        
        if not log_events:
            return []
        
        total_count = len(log_events)
        threat_count = 0
        all_results = []
        
        start_time = time.time()
        
        # 배치 단위로 처리
        for i in range(0, total_count, self.batch_size):
            batch = log_events[i:i + self.batch_size]
            batch_start_time = time.time()
            
            if show_progress:
                logger.info(f"배치 처리 중: {i+1}-{min(i+self.batch_size, total_count)}/{total_count}")
            
            try:
                # 배치 예측 수행
                batch_results = self.detector.predict_batch_with_confidence(batch)
                
                # 결과 보강 (이벤트 정보 추가)
                for j, (log_event, result) in enumerate(zip(batch, batch_results)):
                    enhanced_result = {
                        **result,
                        'prediction_time_ms': (time.time() - batch_start_time) * 1000 / len(batch),
                        'event_info': {
                            'event_name': log_event.get('eventName', 'unknown'),
                            'event_source': log_event.get('eventSource', 'unknown'),
                            'event_time': log_event.get('eventTime', 'unknown'),
                            'user_name': log_event.get('userIdentity', {}).get('userName', 'unknown'),
                            'source_ip': log_event.get('sourceIPAddress', 'unknown')
                        }
                    }
                    
                    if enhanced_result.get('is_threat'):
                        threat_count += 1
                    
                    all_results.append(enhanced_result)
                
                batch_time = time.time() - batch_start_time
                if show_progress:
                    logger.info(f"배치 완료: {len(batch)}개 처리 ({batch_time:.2f}초)")
                    
            except Exception as e:
                logger.error(f"배치 처리 중 오류 (인덱스 {i}): {e}")
                # 오류 발생한 배치는 건너뛰고 계속 진행
                continue
        
        total_time = time.time() - start_time
        
        if show_progress:
            logger.info(f"✅ 최적화된 배치 예측 완료:")
            logger.info(f"  총 로그 수: {total_count}")
            logger.info(f"  위협 탐지: {threat_count}개 ({threat_count/total_count*100:.1f}%)")
            logger.info(f"  처리 시간: {total_time:.2f}초")
            logger.info(f"  평균 속도: {total_count/total_time:.1f} logs/sec")
        
        return all_results

def analyze_database_events_optimized(
    model_path: str, 
    group_id: Optional[str] = None,
    limit: Optional[int] = None,
    min_confidence: float = 0.7,
    save_to_db: bool = True,
    threats_only: bool = False,
    batch_size: int = 5000
):
    """
    최적화된 데이터베이스 기반 위협 분석
    
    Args:
        model_path: 훈련된 모델 파일 경로
        group_id: 분석할 그룹 ID
        limit: 최대 분석할 이벤트 수
        min_confidence: 최소 신뢰도
        save_to_db: 결과를 데이터베이스에 저장할지 여부
        threats_only: 위협만 출력할지 여부
        batch_size: 배치 처리 크기
    """
    logger.info("=" * 60)
    logger.info("최적화된 CloudTrail 위협 탐지 분석 시작")
    logger.info("=" * 60)
    
    # 1. 데이터베이스 연결
    try:
        db_loader = DatabaseDataLoader()
        if not db_loader.validate_connection():
            logger.error("❌ 데이터베이스 연결 실패")
            return
        logger.info("✅ 데이터베이스 연결 성공")
        
    except Exception as e:
        logger.error(f"❌ 데이터베이스 초기화 실패: {e}")
        return
    
    # 2. 최적화된 예측기 초기화
    try:
        predictor = OptimizedCloudTrailPredictor(model_path, batch_size)
    except Exception as e:
        logger.error(f"❌ 예측기 초기화 실패: {e}")
        return
    
    # 3. 데이터 로드
    try:
        with db_loader.get_db_session() as session:
            logger.info("📥 미처리 이벤트 로드 중...")
            logs = db_loader.load_cloudtrail_events(
                group_id=group_id,
                limit=limit,
                unprocessed_only=True
            )
            
            if not logs:
                logger.info("ℹ️  처리할 미처리 이벤트가 없습니다")
                return
                
            logger.info(f"✅ {len(logs)}개의 로그를 로드했습니다")
            
    except Exception as e:
        logger.error(f"❌ 데이터 로드 실패: {e}")
        return
    
    # 4. 최적화된 분석 수행
    try:
        logger.info("🚀 최적화된 위협 분석 수행 중...")
        results = predictor.predict_batch_optimized(logs, show_progress=True)
        
        # 5. 결과 저장 (선택적)
        if save_to_db and results:
            logger.info("💾 결과를 데이터베이스에 저장 중...")
            result_saver = MLResultSaver()
            
            db_results = []
            for log_event, prediction in zip(logs, results):
                event_id = log_event.get('_event_id')
                if event_id and not prediction.get('error'):
                    severity = result_saver.convert_ml_prediction_to_severity(
                        prediction.get('is_threat', False), 
                        prediction.get('confidence', 0.0)
                    )
                    result_data = result_saver.prepare_result_data(prediction, log_event)
                    
                    db_results.append({
                        'event_id': event_id,
                        'severity': severity,
                        'confidence': prediction.get('confidence', 0.0),
                        'result_data': result_data
                    })
            
            if db_results:
                save_stats = result_saver.save_batch_results(db_results, batch_size=1000)
                logger.info(f"✅ 결과 저장 완료: {save_stats['success']}개 성공, {save_stats['failed']}개 실패")
        
        # 6. 결과 요약 출력
        total_count = len(results)
        threat_count = sum(1 for r in results if r.get('is_threat'))
        high_confidence_threats = sum(1 for r in results 
                                    if r.get('is_threat') and r.get('confidence', 0) >= min_confidence)
        
        logger.info("\n" + "=" * 40)
        logger.info("📊 최적화된 분석 결과 요약")
        logger.info("=" * 40)
        logger.info(f"총 로그 수: {total_count:,}")
        logger.info(f"위협 탐지: {threat_count:,}개 ({threat_count/total_count*100:.1f}%)")
        logger.info(f"고신뢰도 위협: {high_confidence_threats:,}개 ({high_confidence_threats/total_count*100:.1f}%)")
        
        # 위협만 출력하는 경우
        if threats_only and high_confidence_threats > 0:
            logger.info(f"\n🔍 고신뢰도 위협 로그 (상위 10개)")
            
            threat_results = [
                (log, result) for log, result in zip(logs, results)
                if result.get('is_threat') and result.get('confidence', 0) >= min_confidence
            ]
            
            # 신뢰도 순으로 정렬
            threat_results.sort(key=lambda x: x[1]['confidence'], reverse=True)
            
            for i, (log, result) in enumerate(threat_results[:10], 1):
                logger.info(f"\n{i}. {log.get('eventName')} - 신뢰도: {result['confidence']:.3f}")
                logger.info(f"   소스: {log.get('eventSource')}")
                logger.info(f"   시간: {log.get('eventTime')}")
                logger.info(f"   사용자: {log.get('userIdentity', {}).get('userName', 'unknown')}")
                logger.info(f"   IP: {log.get('sourceIPAddress')}")
        
    except Exception as e:
        logger.error(f"❌ 분석 중 오류: {e}")
        return
    
    logger.info("\n" + "=" * 60)
    logger.info("🎉 최적화된 분석 완료!")
    logger.info("=" * 60)


def main():
    """최적화된 명령행 인터페이스"""
    parser = argparse.ArgumentParser(
        description="최적화된 CloudTrail 위협 탐지 예측",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--model', type=str, required=True, help='훈련된 모델 파일 경로')
    parser.add_argument('--group-id', type=str, help='분석할 그룹 ID')
    parser.add_argument('--limit', type=int, help='최대 분석할 이벤트 수')
    parser.add_argument('--min-confidence', type=float, default=0.7, help='최소 신뢰도')
    parser.add_argument('--no-save-db', action='store_true', help='데이터베이스 저장 안함')
    parser.add_argument('--threats-only', action='store_true', help='위협만 출력')
    parser.add_argument('--batch-size', type=int, default=5000, help='배치 크기')
    
    args = parser.parse_args()
    
    # 모델 파일 존재 확인
    if not Path(args.model).exists():
        logger.error(f"❌ 모델 파일이 존재하지 않습니다: {args.model}")
        sys.exit(1)
    
    try:
        analyze_database_events_optimized(
            model_path=args.model,
            group_id=args.group_id,
            limit=args.limit,
            min_confidence=args.min_confidence,
            save_to_db=not args.no_save_db,
            threats_only=args.threats_only,
            batch_size=args.batch_size
        )
    except KeyboardInterrupt:
        logger.info("⏹️  사용자에 의해 중단되었습니다")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()