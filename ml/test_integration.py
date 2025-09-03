#!/usr/bin/env python3
"""
개선된 ML 코드 통합 테스트 스크립트
"""

import sys
import os
from pathlib import Path

# 프로젝트 경로 설정
project_root = Path(__file__).parent.parent
ml_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(ml_root))

def test_imports():
    """모든 개선된 모듈의 import 테스트"""
    try:
        print("🔍 모듈 import 테스트 시작...")
        
        # 핵심 ML 모듈
        from src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
        print("✅ CloudTrailThreatDetector import 성공")
        
        # 데이터 로더
        from src.data.db_data_loader import DatabaseDataLoader
        print("✅ DatabaseDataLoader import 성공")
        
        # 결과 저장기
        from src.data.ml_result_saver import MLResultSaver
        print("✅ MLResultSaver import 성공")
        
        print("🎉 모든 모듈 import 성공!")
        return True
        
    except Exception as e:
        print(f"❌ Import 실패: {e}")
        return False

def test_detector_init():
    """탐지기 초기화 테스트"""
    try:
        print("\n🔍 탐지기 초기화 테스트...")
        
        from src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
        
        # 최적화된 탐지기 초기화
        detector = CloudTrailThreatDetector()
        print("✅ CloudTrailThreatDetector 초기화 성공")
        
        # 클래스 상수 확인
        print(f"✅ 위협 도구 수: {len(detector.THREAT_TOOLS)}")
        print(f"✅ 브라우저 수: {len(detector.BROWSERS)}")
        print(f"✅ 의심 키워드 수: {len(detector.SUSPICIOUS_KEYWORDS)}")
        print(f"✅ 고위험 액션 수: {len(detector.HIGH_RISK_ACTIONS)}")
        
        return True
        
    except Exception as e:
        print(f"❌ 탐지기 초기화 실패: {e}")
        return False

def test_feature_extraction():
    """특성 추출 테스트"""
    try:
        print("\n🔍 특성 추출 테스트...")
        
        from src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
        
        detector = CloudTrailThreatDetector()
        
        # 테스트 이벤트
        test_event = {
            'eventTime': '2024-01-15T10:30:00Z',
            'eventSource': 's3.amazonaws.com',
            'eventName': 'CreateUser',
            'awsRegion': 'us-east-1',
            'sourceIPAddress': '203.0.113.12',
            'userIdentity': {
                'type': 'IAMUser',
                'userName': 'test-user'
            },
            'userAgent': 'stratus-red-team',
            'requestParameters': {
                'bucketName': 'test-bucket'
            }
        }
        
        # 단일 특성 추출
        features = detector.extract_features(test_event)
        print(f"✅ 단일 특성 추출 성공: {features.shape}")
        
        # 배치 특성 추출
        batch_events = [test_event] * 5
        batch_features = detector.extract_features_batch(batch_events)
        print(f"✅ 배치 특성 추출 성공: {batch_features.shape}")
        
        # 특성 확인
        print(f"✅ 추출된 특성 수: {len(features.columns)}")
        
        # 위협 특성 확인
        if 'has_threat_tool' in features.columns:
            print(f"✅ 위협 도구 탐지: {features['has_threat_tool'].iloc[0]}")
        
        return True
        
    except Exception as e:
        print(f"❌ 특성 추출 실패: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_result_saver():
    """결과 저장기 테스트"""
    try:
        print("\n🔍 결과 저장기 테스트...")
        
        from src.data.ml_result_saver import MLResultSaver
        
        # 결과 저장기 초기화 (실제 DB 연결 없이)
        saver = MLResultSaver()
        print("✅ MLResultSaver 초기화 성공")
        
        # severity 변환 테스트
        severity_normal = saver.convert_ml_prediction_to_severity(False, 0.3)
        severity_threat = saver.convert_ml_prediction_to_severity(True, 0.8)
        
        print(f"✅ 정상 severity: {severity_normal}")
        print(f"✅ 위협 severity: {severity_threat}")
        
        # result_data 준비 테스트
        test_prediction = {
            'is_threat': True,
            'confidence': 0.85,
            'prediction_time_ms': 95.2
        }
        
        test_event = {
            'eventName': 'CreateUser',
            'eventSource': 'iam.amazonaws.com',
            'eventTime': '2024-01-15T10:30:00Z',
            'sourceIPAddress': '203.0.113.12',
            'userIdentity': {'userName': 'test-user'}
        }
        
        result_data = saver.prepare_result_data(test_prediction, test_event)
        print("✅ result_data 준비 성공")
        print(f"   예측 정보: {result_data.get('prediction', {}).get('is_threat')}")
        print(f"   이벤트 요약: {result_data.get('event_summary', {}).get('event_name')}")
        
        return True
        
    except Exception as e:
        print(f"❌ 결과 저장기 테스트 실패: {e}")
        return False

def main():
    """통합 테스트 실행"""
    print("🚀 ML 코드 개선사항 통합 테스트 시작")
    print("=" * 50)
    
    tests = [
        ("모듈 Import", test_imports),
        ("탐지기 초기화", test_detector_init), 
        ("특성 추출", test_feature_extraction),
        ("결과 저장기", test_result_saver)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📝 {test_name} 테스트 실행중...")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "=" * 50)
    print("📊 테스트 결과 요약")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ 통과" if result else "❌ 실패"
        print(f"{test_name:<20}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 결과: {passed}/{len(tests)} 테스트 통과")
    
    if passed == len(tests):
        print("🎉 모든 테스트 통과! 개선된 코드가 정상 동작합니다.")
        return True
    else:
        print("⚠️ 일부 테스트 실패. 코드를 확인해주세요.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)