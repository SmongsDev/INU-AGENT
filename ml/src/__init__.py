"""
ML 위협 탐지 시스템

CloudTrail 로그에서 위협을 탐지하는 머신러닝 시스템입니다.
데이터베이스와 통합되어 실시간 분석과 결과 저장을 지원합니다.
"""

__version__ = "2.0.0"
__author__ = "INU Security Team"

# 주요 컴포넌트 import
from .core.cloudtrail_threat_detector import CloudTrailThreatDetector
from .data.db_data_loader import DatabaseDataLoader
from .data.ml_result_saver import MLResultSaver

__all__ = [
    "CloudTrailThreatDetector",
    "DatabaseDataLoader",
    "MLResultSaver"
]