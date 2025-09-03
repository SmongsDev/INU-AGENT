#!/usr/bin/env python3
"""
ML 분석 실행 스크립트

분류된 모듈 구조에서 분석 스크립트를 실행하기 위한 진입점입니다.
"""

import sys
import os
from pathlib import Path

# 프로젝트 루트 경로를 Python path에 추가
project_root = Path(__file__).parent.parent  # INU-AGENT 디렉토리
ml_root = Path(__file__).parent  # ml 디렉토리
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(ml_root))

def main():
    """메인 실행 함수"""
    if len(sys.argv) < 2:
        print("사용법: python run_analysis.py <script_name> [arguments]")
        print("사용 가능한 스크립트:")
        print("  predict_threats      - 최적화된 위협 예측 분석")
        print("  batch_analyzer       - 배치 분석")
        print("  train_model          - 모델 훈련") 
        print("  test_detector        - 모델 테스트")
        print("")
        print("예제:")
        print("  python run_analysis.py predict_threats --model models/detector.pkl --batch-size 5000")
        print("  python run_analysis.py batch_analyzer --model models/detector.pkl --once")
        print("  python run_analysis.py train_model --source directory --dir data/")
        sys.exit(1)

    script_name = sys.argv[1]
    script_args = sys.argv[2:]  # 스크립트에 전달할 인수들
    
    # sys.argv를 스크립트 인수로 조정
    sys.argv = [script_name] + script_args
    
    try:
        if script_name == "predict_threats":
            from src.analysis.predict_threats_optimized import main as predict_main
            predict_main()
            
        elif script_name == "batch_analyzer":
            from src.analysis.batch_analyzer import main as batch_main
            batch_main()
            
        elif script_name == "train_model":
            from src.core.train_model import main as train_main
            train_main()
            
        elif script_name == "test_detector":
            from src.core.test_detector import main as test_main
            test_main()
            
        else:
            print(f"❌ 알 수 없는 스크립트: {script_name}")
            print("사용 가능한 스크립트: predict_threats, batch_analyzer, train_model, test_detector")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n⏹️  사용자에 의해 중단되었습니다.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()