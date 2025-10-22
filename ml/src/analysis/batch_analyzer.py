#!/usr/bin/env python3
"""
배치 ML 분석 스크립트

데이터베이스에서 미처리된 이벤트들을 주기적으로 분석하여 ML 결과를 저장합니다.
실시간 분석이나 스케줄링된 배치 작업에 사용할 수 있습니다.
"""

import argparse
import time
import schedule
import signal
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

# 프로젝트 모듈 import
from ..core.cloudtrail_threat_detector import CloudTrailThreatDetector
from ..data.db_data_loader import DatabaseDataLoader
from ..data.ml_result_saver import MLResultSaver


class BatchAnalyzer:
    """
    배치 ML 분석을 수행하는 클래스
    """
    
    def __init__(self, model_path: str, batch_size: int = 1000):
        """
        배치 분석기를 초기화합니다.
        
        Args:
            model_path: 훈련된 ML 모델 파일 경로
            batch_size: 한 번에 처리할 이벤트 수
        """
        self.model_path = model_path
        self.batch_size = batch_size
        self.running = False
        
        # 컴포넌트 초기화
        self.predictor = None
        self.db_loader = None
        self.result_saver = None
        
        # 시그널 핸들러 등록
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """시그널 핸들러"""
        print(f"\n🛑 종료 신호 수신 (시그널: {signum})")
        self.running = False
    
    def initialize(self) -> bool:
        """
        필요한 컴포넌트들을 초기화합니다.
        
        Returns:
            초기화 성공 여부
        """
        try:
            print("🔄 컴포넌트 초기화 중...")
            
            # ML 모델 로드
            print(f"📖 모델 로드 중: {self.model_path}")
            from .predict_threats_optimized import OptimizedCloudTrailPredictor
            self.predictor = OptimizedCloudTrailPredictor(self.model_path)
            
            # 데이터베이스 로더 초기화
            print("🔌 데이터베이스 연결 중...")
            self.db_loader = DatabaseDataLoader()
            if not self.db_loader.validate_connection():
                raise Exception("데이터베이스 연결 실패")
            
            # 결과 저장기 초기화
            print("💾 결과 저장기 초기화 중...")
            self.result_saver = MLResultSaver()
            
            print("✅ 모든 컴포넌트 초기화 완료")
            return True
            
        except Exception as e:
            print(f"❌ 초기화 실패: {e}")
            return False
    
    def analyze_batch(self, 
                     group_id: Optional[str] = None,
                     max_events: Optional[int] = None) -> dict:
        """
        한 번의 배치 분석을 수행합니다.
        
        Args:
            group_id: 분석할 그룹 ID (None이면 모든 그룹)
            max_events: 최대 분석할 이벤트 수
            
        Returns:
            분석 결과 통계
        """
        start_time = time.time()
        
        try:
            # 미처리 이벤트 로드
            print(f"📥 미처리 이벤트 로드 중... (배치 크기: {self.batch_size})")
            
            events = self.db_loader.load_cloudtrail_events(
                group_id=group_id,
                limit=min(self.batch_size, max_events) if max_events else self.batch_size,
                unprocessed_only=True
            )
            
            if not events:
                print("ℹ️  처리할 미처리 이벤트가 없습니다")
                return {'processed': 0, 'threats': 0, 'time': 0}
            
            print(f"🔍 {len(events)}개 이벤트 분석 중...")

            # ML 분석 수행
            results = self.predictor.predict_batch_optimized(events, show_progress=True)
            
            # 결과를 데이터베이스 형식으로 변환
            db_results = []
            threat_count = 0
            
            for event, prediction in zip(events, results):
                if prediction.get('error'):
                    continue

                event_id = event.get('id')
                if not event_id:
                    continue
                
                is_threat = prediction.get('is_threat', False)
                confidence = prediction.get('confidence', 0.0)
                
                if is_threat:
                    threat_count += 1
                
                severity = self.result_saver.convert_ml_prediction_to_severity(is_threat, confidence)
                result_data = self.result_saver.prepare_result_data(prediction, event)
                
                db_results.append({
                    'event_id': event_id,
                    'severity': severity,
                    'confidence': confidence,
                    'result_data': result_data
                })
            
            # 데이터베이스에 결과 저장
            if db_results:
                print(f"💾 {len(db_results)}개 결과 저장 중...")
                save_stats = self.result_saver.save_batch_results(db_results)
                
                processing_time = time.time() - start_time
                
                print(f"✅ 배치 분석 완료:")
                print(f"  처리됨: {len(events)}개")
                print(f"  저장 성공: {save_stats['success']}개")
                print(f"  저장 실패: {save_stats['failed']}개")
                print(f"  위협 탐지: {threat_count}개")
                print(f"  처리 시간: {processing_time:.2f}초")
                
                return {
                    'processed': len(events),
                    'saved': save_stats['success'],
                    'failed': save_stats['failed'],
                    'threats': threat_count,
                    'time': processing_time
                }
            else:
                print("⚠️  저장할 유효한 결과가 없습니다")
                return {'processed': 0, 'threats': 0, 'time': time.time() - start_time}
                
        except Exception as e:
            print(f"❌ 배치 분석 중 오류: {e}")
            return {'error': str(e), 'processed': 0, 'threats': 0, 'time': time.time() - start_time}
    
    def run_continuous(self, 
                      interval_minutes: int = 30,
                      group_id: Optional[str] = None,
                      max_events_per_batch: Optional[int] = None):
        """
        연속적으로 배치 분석을 실행합니다.
        
        Args:
            interval_minutes: 분석 간격 (분)
            group_id: 분석할 그룹 ID
            max_events_per_batch: 배치당 최대 이벤트 수
        """
        print(f"🔄 연속 배치 분석 시작 (간격: {interval_minutes}분)")
        print("Ctrl+C를 눌러 중단할 수 있습니다")
        
        self.running = True
        next_run = datetime.now()
        
        while self.running:
            try:
                current_time = datetime.now()
                
                if current_time >= next_run:
                    print(f"\n⏰ 배치 분석 시작: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # 배치 분석 실행
                    result = self.analyze_batch(group_id, max_events_per_batch)
                    
                    # 다음 실행 시간 설정
                    next_run = current_time + timedelta(minutes=interval_minutes)
                    print(f"⏭️  다음 실행: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # 1초 대기
                time.sleep(1)
                
            except Exception as e:
                print(f"❌ 연속 실행 중 오류: {e}")
                time.sleep(60)  # 오류 발생시 1분 대기 후 재시도
        
        print("🛑 연속 배치 분석이 중단되었습니다")
    
    def run_scheduled(self, schedule_time: str = "02:00"):
        """
        스케줄에 따라 배치 분석을 실행합니다.
        
        Args:
            schedule_time: 실행 시간 (HH:MM 형식)
        """
        print(f"📅 스케줄된 배치 분석 설정: 매일 {schedule_time}")
        print("Ctrl+C를 눌러 중단할 수 있습니다")
        
        # 스케줄 등록
        schedule.every().day.at(schedule_time).do(self._scheduled_analysis)
        
        self.running = True
        
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 1분마다 스케줄 체크
            except Exception as e:
                print(f"❌ 스케줄 실행 중 오류: {e}")
                time.sleep(300)  # 오류 발생시 5분 대기
        
        print("🛑 스케줄된 배치 분석이 중단되었습니다")
    
    def _scheduled_analysis(self):
        """스케줄된 분석 실행"""
        print(f"\n📅 예약된 배치 분석 시작: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        result = self.analyze_batch()
        print(f"📅 예약된 배치 분석 완료")
    
    def get_statistics(self, group_id: Optional[str] = None):
        """현재 ML 분석 통계를 출력합니다."""
        if not self.result_saver:
            print("❌ 결과 저장기가 초기화되지 않았습니다")
            return
        
        print("📊 ML 분석 통계 조회 중...")
        stats = self.result_saver.get_ml_statistics(group_id)
        
        if not stats:
            print("❌ 통계를 조회할 수 없습니다")
            return
        
        print(f"\n=== ML 분석 통계 ===")
        print(f"총 분석된 이벤트: {stats.get('total_analyzed', 0)}")
        print(f"위협 탐지: {stats.get('threat_count', 0)}개 ({stats.get('threat_percentage', 0)}%)")
        
        severity_dist = stats.get('severity_distribution', {})
        if severity_dist:
            print("심각도별 분포:")
            severity_names = ['정상', 'low', 'middle', 'high']
            for severity in range(4):
                count = severity_dist.get(severity, 0)
                name = severity_names[severity]
                print(f"  {name}(L{severity}): {count}개")
        
        confidence_stats = stats.get('confidence_stats', {})
        if confidence_stats:
            print(f"위협 탐지 신뢰도 통계:")
            print(f"  최소: {confidence_stats.get('min', 0):.3f}")
            print(f"  최대: {confidence_stats.get('max', 0):.3f}")
            print(f"  평균: {confidence_stats.get('avg', 0):.3f}")


def main():
    """명령행 인터페이스"""
    parser = argparse.ArgumentParser(
        description="배치 ML 분석",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:

# 한 번만 배치 분석 실행
python batch_analyzer.py --model models/detector.pkl --once

# 30분마다 연속 분석
python batch_analyzer.py --model models/detector.pkl --continuous --interval 30

# 매일 새벽 2시에 스케줄 분석
python batch_analyzer.py --model models/detector.pkl --scheduled --schedule-time "02:00"

# 특정 그룹만 분석
python batch_analyzer.py --model models/detector.pkl --once --group-id "uuid-here"

# 배치 크기 조정
python batch_analyzer.py --model models/detector.pkl --once --batch-size 500

# 통계 조회만
python batch_analyzer.py --model models/detector.pkl --stats
        """
    )
    
    parser.add_argument(
        '--model', 
        type=str, 
        required=True,
        help='훈련된 모델 파일 경로'
    )
    
    parser.add_argument(
        '--once', 
        action='store_true',
        help='한 번만 배치 분석 실행'
    )
    
    parser.add_argument(
        '--continuous', 
        action='store_true',
        help='연속 배치 분석 실행'
    )
    
    parser.add_argument(
        '--scheduled', 
        action='store_true',
        help='스케줄된 배치 분석 실행'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=30,
        help='연속 분석 간격 (분, 기본값: 30)'
    )
    
    parser.add_argument(
        '--schedule-time',
        type=str,
        default="02:00",
        help='스케줄 분석 시간 (HH:MM, 기본값: 02:00)'
    )
    
    parser.add_argument(
        '--group-id',
        type=str,
        help='분석할 그룹 ID'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='배치 크기 (기본값: 1000)'
    )
    
    parser.add_argument(
        '--max-events',
        type=int,
        help='최대 분석할 이벤트 수'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='통계만 조회'
    )
    
    args = parser.parse_args()
    
    # 모델 파일 존재 확인
    if not Path(args.model).exists():
        print(f"❌ 모델 파일이 존재하지 않습니다: {args.model}")
        sys.exit(1)
    
    # 배치 분석기 초기화
    analyzer = BatchAnalyzer(args.model, args.batch_size)
    
    if not analyzer.initialize():
        print("❌ 초기화 실패")
        sys.exit(1)
    
    # 모드에 따른 실행
    try:
        if args.stats:
            # 통계만 조회
            analyzer.get_statistics(args.group_id)
            
        elif args.once:
            # 한 번만 실행
            print("🚀 단일 배치 분석 실행")
            result = analyzer.analyze_batch(args.group_id, args.max_events)
            if 'error' in result:
                sys.exit(1)
                
        elif args.continuous:
            # 연속 실행
            analyzer.run_continuous(args.interval, args.group_id, args.max_events)
            
        elif args.scheduled:
            # 스케줄 실행
            analyzer.run_scheduled(args.schedule_time)
            
        else:
            parser.error("--once, --continuous, --scheduled, --stats 중 하나는 필수입니다")
    
    except KeyboardInterrupt:
        print(f"\n⏹️  사용자에 의해 중단되었습니다")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()