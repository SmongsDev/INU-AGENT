#!/usr/bin/env python3
"""
단일 CloudTrail JSON 파일에 대한 위협 탐지 예측 스크립트
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List, Dict, Any

# 프로젝트 루트를 시스템 경로에 추가
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from ml.src.core.cloudtrail_threat_detector import CloudTrailThreatDetector
from ml.src.data.file_data_loader import CloudTrailDataLoader


class SingleFilePredictor:
    """단일 파일에 대한 CloudTrail 위협 예측 클래스"""
    
    def __init__(self, model_path: str):
        """
        예측기를 초기화합니다.
        
        Args:
            model_path: 훈련된 모델 파일 경로
        """
        self.model_path = model_path
        self.detector = CloudTrailThreatDetector()
        self._load_model()
    
    def _load_model(self):
        """모델을 로드합니다."""
        if not Path(self.model_path).exists():
            raise FileNotFoundError(f"모델 파일이 없습니다: {self.model_path}")
        
        print(f"📖 모델 로드 중: {self.model_path}")
        self.detector.load_model(self.model_path)
        print("✅ 모델 로드 완료")
    
    def predict_file(self, file_path: str, min_confidence: float = 0.7, 
                    threats_only: bool = False) -> Dict[str, Any]:
        """
        파일의 모든 로그에 대해 위협 예측을 수행합니다.
        
        Args:
            file_path: 분석할 JSON 파일 경로
            min_confidence: 최소 신뢰도 임계값
            threats_only: 위협만 표시할지 여부
            
        Returns:
            예측 결과 요약
        """
        # 파일 로드
        loader = CloudTrailDataLoader()
        records = loader.load_from_json_file(file_path)
        
        if not records:
            return {'error': '로드된 레코드가 없습니다'}
        
        # 로그 검증
        valid_records = loader.validate_logs(records)
        if not valid_records:
            return {'error': '유효한 레코드가 없습니다'}
        
        print(f"\n🔍 위협 탐지 분석 시작...")
        print(f"📁 파일: {file_path}")
        print(f"📊 총 로그 수: {len(records)} (유효: {len(valid_records)})")
        print("-" * 60)
        
        # 배치 예측 수행
        try:
            results = self.detector.predict_batch_with_confidence(valid_records)
        except Exception as e:
            return {'error': f'예측 중 오류: {e}'}
        
        # 결과 분석
        threat_count = 0
        high_confidence_threats = []
        all_results = []
        
        for i, (record, result) in enumerate(zip(valid_records, results), 1):
            if result.get('error'):
                print(f"⚠️  레코드 #{i} 분석 중 오류: {result['error']}")
                continue
            
            is_threat = result.get('is_threat', False)
            confidence = result.get('confidence', 0.0)
            
            event_name = record.get('eventName', 'Unknown')
            event_source = record.get('eventSource', 'Unknown')
            user_agent = record.get('userAgent', 'Unknown')
            source_ip = record.get('sourceIPAddress', 'Unknown')
            event_time = record.get('eventTime', 'Unknown')
            user_name = record.get('userIdentity', {}).get('userName', 'Unknown')
            
            result_info = {
                'index': i,
                'event_name': event_name,
                'event_source': event_source,
                'event_time': event_time,
                'user_name': user_name,
                'user_agent': user_agent,
                'source_ip': source_ip,
                'is_threat': is_threat,
                'confidence': confidence,
                'threat_score': result.get('threat_score', 0)
            }
            all_results.append(result_info)
            
            if is_threat and confidence >= min_confidence:
                threat_count += 1
                high_confidence_threats.append(result_info)
                
                print(f"🚨 위협 탐지 #{threat_count}:")
                print(f"   이벤트: {event_name}")
                print(f"   소스: {event_source}")
                print(f"   시간: {event_time}")
                print(f"   사용자: {user_name}")
                print(f"   신뢰도: {confidence:.3f}")
                print(f"   User Agent: {user_agent}")
                print(f"   IP: {source_ip}")
                print()
            
            elif not threats_only:
                status = "⚠️ " if is_threat else "✅"
                print(f"{status} #{i}: {event_name} (신뢰도: {confidence:.3f})")
        
        # 결과 요약
        total_analyzed = len(valid_records)
        all_threats = sum(1 for r in all_results if r['is_threat'])
        
        print("-" * 60)
        print(f"📊 분석 완료!")
        print(f"   전체 로그: {len(records)}개")
        print(f"   유효 로그: {total_analyzed}개")
        print(f"   전체 위협: {all_threats}개")
        print(f"   고신뢰도 위협: {threat_count}개 (≥{min_confidence})")
        print(f"   위협 비율: {(all_threats/total_analyzed)*100:.1f}%")
        
        if high_confidence_threats:
            print(f"\n🔥 상위 위협 이벤트 (신뢰도 순):")
            sorted_threats = sorted(high_confidence_threats, key=lambda x: x['confidence'], reverse=True)
            for i, threat in enumerate(sorted_threats[:5], 1):
                print(f"{i}. {threat['event_name']} (신뢰도: {threat['confidence']:.3f})")
        
        return {
            'file_path': file_path,
            'total_logs': len(records),
            'valid_logs': total_analyzed,
            'all_threats': all_threats,
            'high_confidence_threats': threat_count,
            'threat_percentage': (all_threats/total_analyzed)*100,
            'threat_details': high_confidence_threats,
            'all_results': all_results
        }


def main():
    """명령행 인터페이스"""
    parser = argparse.ArgumentParser(
        description="단일 CloudTrail JSON 파일 위협 탐지",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  # 기본 분석
  python predict_single_file.py --model models/detector.pkl --file logs/cloudtrail.json

  # 위협만 표시
  python predict_single_file.py --model models/detector.pkl --file logs/cloudtrail.json --threats-only

  # 신뢰도 임계값 조정
  python predict_single_file.py --model models/detector.pkl --file logs/cloudtrail.json --min-confidence 0.8
        """
    )
    
    parser.add_argument('--model', type=str, required=True, 
                       help='훈련된 모델 파일 경로')
    parser.add_argument('--file', type=str, required=True, 
                       help='분석할 CloudTrail JSON 파일 경로')
    parser.add_argument('--min-confidence', type=float, default=0.7, 
                       help='위협 탐지 최소 신뢰도 (기본값: 0.7)')
    parser.add_argument('--threats-only', action='store_true', 
                       help='위협으로 탐지된 로그만 표시')
    
    args = parser.parse_args()
    
    # 파일 존재 확인
    if not Path(args.model).exists():
        print(f"❌ 모델 파일이 존재하지 않습니다: {args.model}")
        sys.exit(1)
    
    if not Path(args.file).exists():
        print(f"❌ JSON 파일이 존재하지 않습니다: {args.file}")
        sys.exit(1)
    
    try:
        # 예측 수행
        predictor = SingleFilePredictor(args.model)
        result = predictor.predict_file(
            file_path=args.file,
            min_confidence=args.min_confidence,
            threats_only=args.threats_only
        )
        
        if 'error' in result:
            print(f"❌ {result['error']}")
            sys.exit(1)
        
        print(f"\n✅ 분석 완료! 총 {result['high_confidence_threats']}개의 고신뢰도 위협을 탐지했습니다.")
        
    except KeyboardInterrupt:
        print("\n⏹️  사용자에 의해 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()