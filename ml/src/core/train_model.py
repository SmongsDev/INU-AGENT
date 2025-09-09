#!/usr/bin/env python3
"""
CloudTrail 위협 탐지 모델 훈련 스크립트

실제 CloudTrail JSON 데이터로 위협 탐지 모델을 훈련하고 저장합니다.
"""

import argparse
import sys
from pathlib import Path
from ..data.file_data_loader import CloudTrailDataLoader
from .cloudtrail_threat_detector import CloudTrailThreatDetector


def train_threat_detection_model(
    data_source: str,
    file_path: str = None,
    directory_path: str = None,
    model_output_path: str = "ml/models/cloudTrail_v1.pkl",
    min_logs: int = 100,
    time_filter_start: str = None,
    time_filter_end: str = None
):
    """
    CloudTrail 위협 탐지 모델을 훈련합니다.
    
    Args:
        data_source: 데이터 소스 ('json_file' 또는 'directory')
        file_path: JSON 파일 경로 (data_source가 'json_file'인 경우)
        directory_path: JSON 파일들이 있는 디렉토리 경로 (data_source가 'directory'인 경우)
        model_output_path: 훈련된 모델을 저장할 경로
        min_logs: 최소 로그 수 (이보다 적으면 경고)
        time_filter_start: 시작 시간 필터 (ISO 형식)
        time_filter_end: 종료 시간 필터 (ISO 형식)
    
    Returns:
        훈련된 CloudTrailThreatDetector 객체
    """
    
    print("=" * 60)
    print("CloudTrail 위협 탐지 모델 훈련 시작")
    print("=" * 60)
    
    # 1. 데이터 로드
    print("\n1단계: 데이터 로딩")
    print("-" * 30)
    
    loader = CloudTrailDataLoader()
    
    if data_source == 'json_file':
        if not file_path:
            raise ValueError("json_file 모드에서는 file_path가 필요합니다")
        logs = loader.load_from_json_file(file_path)
        print(f"파일에서 로드: {file_path}")
        
    elif data_source == 'directory':
        if not directory_path:
            raise ValueError("directory 모드에서는 directory_path가 필요합니다")
        logs = loader.load_from_directory(directory_path)
        print(f"디렉토리에서 로드: {directory_path}")
        
    else:
        raise ValueError(f"지원하지 않는 데이터 소스: {data_source}")
    
    if not logs:
        print("❌ 로드된 로그가 없습니다.")
        return None
    
    print(f"✅ 총 {len(logs)}개의 원본 로그를 로드했습니다")
    
    # 2. 데이터 검증
    print("\n2단계: 데이터 검증")
    print("-" * 30)
    
    valid_logs = loader.validate_logs(logs)
    
    if len(valid_logs) < min_logs:
        print(f"⚠️  경고: 유효한 로그 수({len(valid_logs)})가 권장 최소값({min_logs})보다 적습니다.")
        print("   모델 성능이 제한적일 수 있습니다.")
        
        user_input = input("계속 진행하시겠습니까? (y/N): ")
        if user_input.lower() != 'y':
            print("훈련을 중단합니다.")
            return None
    
    # 3. 시간 필터링 (선택사항)
    if time_filter_start or time_filter_end:
        print("\n3단계: 시간 필터링")
        print("-" * 30)
        
        filtered_logs = loader.filter_logs_by_time(
            valid_logs, 
            time_filter_start, 
            time_filter_end
        )
        valid_logs = filtered_logs
        
        if len(valid_logs) == 0:
            print("❌ 시간 필터링 후 로그가 없습니다.")
            return None
    
    # 4. 데이터 요약 출력
    print(f"\n4단계: 데이터 요약")
    print("-" * 30)
    
    summary = loader.get_data_summary(valid_logs)
    
    print(f"최종 훈련 로그 수: {summary['total_logs']}")
    print(f"시간 범위: {summary['time_range'].get('earliest', 'N/A')} ~ {summary['time_range'].get('latest', 'N/A')}")
    print(f"고유 User Agent 수: {summary['unique_user_agents']}")
    
    print("\n주요 이벤트 소스:")
    for source, count in list(summary['top_event_sources'].items())[:5]:
        percentage = (count / summary['total_logs']) * 100
        print(f"  {source}: {count}개 ({percentage:.1f}%)")
    
    print("\n주요 이벤트 이름:")
    for name, count in list(summary['top_event_names'].items())[:5]:
        percentage = (count / summary['total_logs']) * 100
        print(f"  {name}: {count}개 ({percentage:.1f}%)")
    
    # 5. 모델 훈련
    print(f"\n5단계: 모델 훈련")
    print("-" * 30)
    
    detector = CloudTrailThreatDetector(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    print("Random Forest 모델 초기화 완료")
    print("자동 라벨링 및 훈련을 시작합니다...")
    
    # 훈련 실행
    training_results = detector.train(valid_logs)
    
    # 6. 훈련 결과 출력
    print(f"\n6단계: 훈련 결과")
    print("-" * 30)
    
    cv_mean = training_results['cv_mean']
    cv_std = training_results['cv_std']
    
    print(f"✅ 훈련이 성공적으로 완료되었습니다!")
    print(f"교차 검증 F1 점수: {cv_mean:.4f} (±{cv_std * 2:.4f})")
    
    # 성능 평가
    if cv_mean >= 0.9:
        print("🎉 우수한 성능! 모델이 매우 잘 훈련되었습니다.")
    elif cv_mean >= 0.7:
        print("👍 양호한 성능! 실용적으로 사용 가능합니다.")
    else:
        print("⚠️  성능이 제한적입니다. 더 많은 다양한 데이터가 필요할 수 있습니다.")
    
    # 7. 모델 저장
    print(f"\n7단계: 모델 저장")
    print("-" * 30)
    
    # 출력 디렉토리 생성
    output_path = Path(model_output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    detector.save_model(str(output_path))
    
    print(f"✅ 모델이 저장되었습니다: {output_path}")
    print(f"   파일 크기: {output_path.stat().st_size / 1024 / 1024:.2f} MB")
    
    # 8. 사용법 안내
    print(f"\n8단계: 사용법 안내")
    print("-" * 30)
    
    print("훈련된 모델 사용 방법:")
    print(f"""
from src.predict_threats import CloudTrailPredictor

# 모델 로드
predictor = CloudTrailPredictor('{output_path}')

# 단일 로그 예측
result = predictor.predict_single(your_log_event)
print(f"위협 여부: {{result['is_threat']}}")
print(f"신뢰도: {{result['confidence']:.3f}}")

# 여러 로그 배치 예측
results = predictor.predict_batch(log_list)
""")
    
    print("=" * 60)
    print("모델 훈련 완료!")
    print("=" * 60)
    
    return detector


def main():
    """명령행 인터페이스"""
    parser = argparse.ArgumentParser(
        description="CloudTrail 위협 탐지 모델 훈련",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  # 단일 JSON 파일로 훈련
  python train_model.py --source json_file --file data/cloudtrail.json

  # 디렉토리의 모든 JSON 파일로 훈련  
  python train_model.py --source directory --dir data/logs/

  # 시간 필터링과 함께 훈련
  python train_model.py --source directory --dir data/logs/ \\
    --start-time "2024-01-01T00:00:00Z" \\
    --end-time "2024-01-31T23:59:59Z"

  # 커스텀 모델 저장 경로
  python train_model.py --source json_file --file data/cloudtrail.json \\
    --output ml/models/my_detector.pkl
        """
    )
    
    parser.add_argument(
        '--source', 
        choices=['json_file', 'directory'], 
        required=True,
        help='데이터 소스 타입'
    )
    
    parser.add_argument(
        '--file', 
        type=str,
        help='JSON 파일 경로 (--source json_file인 경우 필수)'
    )
    
    parser.add_argument(
        '--dir', 
        type=str,
        help='JSON 파일들이 있는 디렉토리 경로 (--source directory인 경우 필수)'
    )
    
    parser.add_argument(
        '--output', 
        type=str, 
        default='ml/models/cloudtrail_threat_0901.pkl',
        help='훈련된 모델을 저장할 경로 (기본값: ml/models/cloudtrail_threat_detector.pkl)'
    )
    
    parser.add_argument(
        '--min-logs', 
        type=int, 
        default=100,
        help='최소 로그 수 (기본값: 100)'
    )
    
    parser.add_argument(
        '--start-time', 
        type=str,
        help='시작 시간 필터 (ISO 형식, 예: 2024-01-01T00:00:00Z)'
    )
    
    parser.add_argument(
        '--end-time', 
        type=str,
        help='종료 시간 필터 (ISO 형식, 예: 2024-01-31T23:59:59Z)'
    )
    
    args = parser.parse_args()
    
    # 인자 검증
    if args.source == 'json_file' and not args.file:
        parser.error("--source json_file인 경우 --file이 필요합니다")
    
    if args.source == 'directory' and not args.dir:
        parser.error("--source directory인 경우 --dir이 필요합니다")
    
    # 파일/디렉토리 존재 확인
    if args.source == 'json_file':
        if not Path(args.file).exists():
            print(f"❌ 파일이 존재하지 않습니다: {args.file}")
            sys.exit(1)
    
    if args.source == 'directory':
        if not Path(args.dir).exists():
            print(f"❌ 디렉토리가 존재하지 않습니다: {args.dir}")
            sys.exit(1)
    
    # 모델 훈련 실행
    try:
        detector = train_threat_detection_model(
            data_source=args.source,
            file_path=args.file,
            directory_path=args.dir,
            model_output_path=args.output,
            min_logs=args.min_logs,
            time_filter_start=args.start_time,
            time_filter_end=args.end_time
        )
        
        if detector:
            print(f"\n🎉 성공적으로 완료되었습니다!")
            sys.exit(0)
        else:
            print(f"\n❌ 모델 훈련에 실패했습니다.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n⏹️  사용자에 의해 중단되었습니다.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()