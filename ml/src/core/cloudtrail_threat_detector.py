import pandas as pd
import numpy as np
import json
import joblib
from datetime import datetime
from typing import Dict, List, Union, Tuple, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import warnings
from functools import lru_cache
import logging

warnings.filterwarnings('ignore')

# 로거 설정
logger = logging.getLogger(__name__)


class CloudTrailThreatDetector:
    """
    실시간 로그 분석을 위한 Random Forest 기반 CloudTrail 위협 탐지 모델.
    
    단일 CloudTrail 로그 이벤트에 대해 이진 분류를 수행합니다:
    - True: 위협 탐지됨 (추가 분석 필요)
    - False: 정상 활동 (필터링 가능)
    """
    
    # 클래스 레벨 상수 - 성능 최적화
    THREAT_TOOLS = frozenset([
        'stratus-red-team', 'atomic-red-team', 'metasploit', 'nmap', 
        'sqlmap', 'burp', 'curl', 'python-requests', 'boto3', 'aws-cli'
    ])
    
    BROWSERS = frozenset(['mozilla', 'chrome', 'firefox', 'safari', 'edge'])
    
    SUSPICIOUS_KEYWORDS = frozenset([
        'test', 'temp', 'stratus', 'red', 'attack', 'exploit'
    ])
    
    HIGH_RISK_ACTIONS = frozenset([
        'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
        'CreateRole', 'DeleteRole', 'PutBucketPolicy', 'DeleteBucket',
        'CreateAccessKey', 'DeleteAccessKey', 'AssumeRole'
    ])
    
    def __init__(self, **rf_params):
        """
        CloudTrail 위협 탐지기를 초기화합니다.
        
        Args:
            **rf_params: Random Forest 매개변수 (n_estimators, max_depth 등)
        """
        default_params = {
            'n_estimators': 100,
            'max_depth': 10,
            'random_state': 42,
            'n_jobs': -1,
            'class_weight': 'balanced'
        }
        default_params.update(rf_params)
        
        self.model = RandomForestClassifier(**default_params)
        self.label_encoders = {}
        self.feature_names = []
        self.feature_importance_ = None
        self.is_trained = False
        
    def extract_features(self, log_event: Dict) -> pd.DataFrame:
        """
        단일 CloudTrail 로그 이벤트에서 특성을 추출합니다.

        Args:
            log_event: 딕셔너리 형태의 CloudTrail 로그 이벤트

        Returns:
            추출된 특성이 포함된 DataFrame (1행)
        """
        features = {}

        # 기본 이벤트 정보 (snake_case + camelCase 호환)
        features['event_source'] = log_event.get('event_source') or log_event.get('eventSource', 'unknown')
        features['event_name'] = log_event.get('event_name') or log_event.get('eventName', 'unknown')
        features['aws_region'] = log_event.get('aws_region') or log_event.get('awsRegion', 'unknown')
        features['read_only'] = log_event.get('read_only') if log_event.get('read_only') is not None else log_event.get('readOnly', False)
        features['management_event'] = log_event.get('management_event') if log_event.get('management_event') is not None else log_event.get('managementEvent', False)

        # 사용자 신원 특성 (snake_case + camelCase 호환)
        user_identity = log_event.get('user_identity') or log_event.get('userIdentity', {})
        if isinstance(user_identity, str):
            import json
            try:
                user_identity = json.loads(user_identity)
            except:
                user_identity = {}
        features['user_type'] = user_identity.get('type', 'unknown')
        features['user_name'] = user_identity.get('userName', 'unknown')
        features['access_key_id'] = user_identity.get('accessKeyId', 'unknown')

        # 네트워크 특성 (snake_case + camelCase 호환)
        features['source_ip'] = log_event.get('source_ip') or log_event.get('sourceIPAddress', 'unknown')
        features['user_agent'] = log_event.get('user_agent') or log_event.get('userAgent', 'unknown')
        
        # 시간 특성 제거 (AWS 시간대 불일치 문제로 인해)

        # 에러 특성
        error_code = log_event.get('error_code') or log_event.get('errorCode')
        features['has_error_code'] = error_code is not None and error_code != ''
        features['is_access_denied'] = error_code == 'AccessDenied'

        # 고급 위협 탐지 특성 - 최적화된 버전
        user_agent_lower = features['user_agent'].lower()

        # 위협 도구 탐지 - frozenset 사용으로 최적화
        features['has_threat_tool'] = any(tool in user_agent_lower for tool in self.THREAT_TOOLS)

        # 브라우저 vs 프로그래매틱 접근 - frozenset 사용으로 최적화
        features['is_browser_access'] = any(browser in user_agent_lower for browser in self.BROWSERS)
        features['is_programmatic'] = not features['is_browser_access'] and user_agent_lower != 'unknown'

        # 의심스러운 리소스 패턴 - 최적화
        request_params = log_event.get('request_parameters') or log_event.get('requestParameters', {})
        if isinstance(request_params, str):
            import json
            try:
                request_params = json.loads(request_params)
            except:
                request_params = {}
        bucket_name = ''

        if isinstance(request_params, dict):
            bucket_name = request_params.get('bucketName', '').lower()

        features['has_suspicious_resource'] = any(keyword in bucket_name for keyword in self.SUSPICIOUS_KEYWORDS)
        
        # 네트워크 분류 - 최적화
        source_ip = features['source_ip']
        features['is_internal_ip'] = source_ip.startswith(('10.', '192.168.'))
        features['is_aws_ip'] = source_ip.startswith(('52.', '54.', '3.', '13.', '18.'))
        
        # 고위험 액션 - frozenset 사용으로 최적화
        features['is_high_risk_action'] = features['event_name'] in self.HIGH_RISK_ACTIONS
        
        # DataFrame으로 변환
        df = pd.DataFrame([features])
        return df
    
    def _create_rule_based_labels(self, logs_data: List[Dict]) -> np.ndarray:
        """
        훈련 데이터를 위한 규칙 기반 라벨을 생성합니다.
        
        Args:
            logs_data: CloudTrail 로그 이벤트 리스트
            
        Returns:
            라벨 배열 (1: 위협, 0: 정상)
        """
        labels = []
        
        for log_event in logs_data:
            features_df = self.extract_features(log_event)
            features = features_df.iloc[0]
            
            is_threat = False
            
            # 규칙 1: Red Team 도구
            if features['has_threat_tool']:
                is_threat = True
            
            # 규칙 2: Red Team 관련 버킷 접근
            if features['has_suspicious_resource']:
                is_threat = True
            
            # 규칙 3: AccessDenied + 의심스러운 리소스 조합
            if features['is_access_denied'] and features['has_suspicious_resource']:
                is_threat = True
            
            # 규칙 4: 프로그래매틱 + 고위험 액션 (시간 조건 제거)
            if (features['is_programmatic'] and
                features['is_high_risk_action']):
                is_threat = True
            
            # 규칙 5: 다중 의심 지표 (시간 관련 제거)
            suspicious_count = sum([
                features['has_error_code'],
                features['is_programmatic'],
                features['is_high_risk_action'],
                features['has_suspicious_resource']
            ])
            
            if suspicious_count >= 3:
                is_threat = True
            
            labels.append(1 if is_threat else 0)
        
        return np.array(labels)
    
    def _prepare_features(self, features_df: pd.DataFrame, is_training: bool = False) -> pd.DataFrame:
        """
        라벨 인코딩을 사용하여 훈련 또는 예측을 위한 특성을 준비합니다.
        
        Args:
            features_df: 추출된 특성이 포함된 DataFrame
            is_training: 훈련용인지(인코더 학습) 예측용인지(변환만) 여부
            
        Returns:
            인코딩된 특성이 포함된 DataFrame
        """
        df = features_df.copy()
        
        categorical_columns = ['event_source', 'event_name', 'aws_region', 'user_type', 
                             'user_name', 'access_key_id', 'source_ip', 'user_agent']
        
        for col in categorical_columns:
            if col in df.columns:
                if is_training:
                    if col not in self.label_encoders:
                        self.label_encoders[col] = LabelEncoder()
                    
                    # 알려지지 않은 값들을 인코더에 추가하여 처리
                    unique_values = df[col].unique()
                    try:
                        df[col] = self.label_encoders[col].fit_transform(df[col])
                    except:
                        # fit_transform이 실패하면 알려지지 않은 값들 처리
                        known_values = getattr(self.label_encoders[col], 'classes_', [])
                        if len(known_values) == 0:
                            df[col] = self.label_encoders[col].fit_transform(df[col])
                        else:
                            # 훈련 중 새로운 값들 처리
                            new_values = set(unique_values) - set(known_values)
                            if new_values:
                                extended_values = list(known_values) + list(new_values)
                                self.label_encoders[col].classes_ = np.array(extended_values)
                            df[col] = self.label_encoders[col].transform(df[col])
                else:
                    # 예측을 위해 알려지지 않은 값들 처리
                    if col in self.label_encoders:
                        known_classes = self.label_encoders[col].classes_
                        df[col] = df[col].apply(lambda x: x if x in known_classes else known_classes[0])
                        df[col] = self.label_encoders[col].transform(df[col])
                    else:
                        # 인코더가 존재하지 않으면 기본 인코딩 사용
                        df[col] = 0
        
        return df
    
    def extract_features_batch(self, log_events: List[Dict]) -> pd.DataFrame:
        """
        여러 로그 이벤트의 특성을 배치로 추출합니다. (성능 최적화)
        
        Args:
            log_events: CloudTrail 로그 이벤트 리스트
            
        Returns:
            추출된 특성들이 포함된 DataFrame
        """
        if not log_events:
            return pd.DataFrame()
        
        features_list = []
        for log_event in log_events:
            features_df = self.extract_features(log_event)
            features_list.append(features_df)
        
        return pd.concat(features_list, ignore_index=True) if features_list else pd.DataFrame()
    
    def train(self, logs_data: List[Dict], labels: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        CloudTrail 로그로 Random Forest 모델을 훈련합니다.
        
        Args:
            logs_data: CloudTrail 로그 이벤트 리스트
            labels: 선택적 라벨 배열. None이면 규칙 기반 라벨링 사용
            
        Returns:
            성능 지표를 포함한 훈련 결과
        """
        logger.info("로그에서 특성을 추출하는 중...")
        
        # 배치 처리로 특성 추출 최적화
        batch_size = 1000
        all_features_list = []
        
        for i in range(0, len(logs_data), batch_size):
            batch = logs_data[i:i + batch_size]
            logger.info(f"처리된 로그: {i}/{len(logs_data)}")
            
            batch_features = self.extract_features_batch(batch)
            if not batch_features.empty:
                all_features_list.append(batch_features)
        
        # 모든 특성 결합
        all_features = pd.concat(all_features_list, ignore_index=True) if all_features_list else pd.DataFrame()
        print(f"추출된 특성 형태: {all_features.shape}")
        
        # 라벨이 제공되지 않은 경우 생성
        if labels is None:
            print("규칙 기반 라벨을 생성하는 중...")
            labels = self._create_rule_based_labels(logs_data)
        
        # 특성 준비
        print("범주형 특성을 인코딩하는 중...")
        X = self._prepare_features(all_features, is_training=True)
        y = labels
        
        self.feature_names = list(X.columns)
        
        print(f"훈련 데이터 형태: {X.shape}")
        print(f"라벨 분포: {np.bincount(y)}")
        
        # 평가를 위한 데이터 분할
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # 모델 훈련
        print("Random Forest 모델을 훈련하는 중...")
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # 특성 중요도 획득
        self.feature_importance_ = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        # 교차 검증
        print("교차 검증을 수행하는 중...")
        cv_scores = cross_val_score(self.model, X, y, cv=5, scoring='f1')
        
        # 테스트 세트 평가
        y_pred = self.model.predict(X_test)
        
        # 결과 준비
        results = {
            'cv_scores': cv_scores,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'test_classification_report': classification_report(y_test, y_pred),
            'test_confusion_matrix': confusion_matrix(y_test, y_pred),
            'feature_importance': self.feature_importance_
        }
        
        print(f"\n훈련이 완료되었습니다!")
        print(f"교차 검증 F1 점수: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        print(f"\n상위 10개 중요 특성:")
        print(self.feature_importance_.head(10))
        print(f"\n테스트 세트 분류 보고서:")
        print(results['test_classification_report'])
        
        return results
    
    def predict(self, log_event: Dict) -> bool:
        """
        단일 로그 이벤트가 위협인지 예측합니다.
        
        Args:
            log_event: 딕셔너리 형태의 CloudTrail 로그 이벤트
            
        Returns:
            Boolean (True: 위협, False: 정상)
        """
        if not self.is_trained:
            raise ValueError("예측하기 전에 모델을 훈련해야 합니다")
        
        # 특성 추출 및 준비
        features_df = self.extract_features(log_event)
        X = self._prepare_features(features_df, is_training=False)
        
        # 예측 수행
        prediction = self.model.predict(X)[0]
        return bool(prediction)
    
    def predict_batch_with_confidence(self, log_events: List[Dict]) -> List[Dict[str, Union[bool, float]]]:
        """
        여러 로그 이벤트에 대해 배치로 예측합니다. (성능 최적화)
        
        Args:
            log_events: CloudTrail 로그 이벤트 리스트
            
        Returns:
            예측 결과 리스트
        """
        if not self.is_trained:
            raise ValueError("예측하기 전에 모델을 훈련해야 합니다")
        
        if not log_events:
            return []
        
        # 배치로 특성 추출
        features_df = self.extract_features_batch(log_events)
        if features_df.empty:
            return []
        
        # 배치로 특성 준비
        X = self._prepare_features(features_df, is_training=False)
        
        # 배치 예측 수행
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        results = []
        for i, (prediction, probs) in enumerate(zip(predictions, probabilities)):
            confidence = max(probs)
            results.append({
                'is_threat': bool(prediction),
                'confidence': float(confidence)
            })
        
        return results
    
    def predict_with_confidence(self, log_event: Dict) -> Dict[str, Union[bool, float]]:
        """
        단일 로그 이벤트에 대해 신뢰도 점수와 함께 예측합니다.
        
        Args:
            log_event: 딕셔너리 형태의 CloudTrail 로그 이벤트
            
        Returns:
            예측 결과와 신뢰도 점수가 포함된 딕셔너리
        """
        if not self.is_trained:
            raise ValueError("예측하기 전에 모델을 훈련해야 합니다")
        
        # 특성 추출 및 준비
        features_df = self.extract_features(log_event)
        X = self._prepare_features(features_df, is_training=False)
        
        # 확률과 함께 예측 수행
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = max(probabilities)
        
        return {
            'is_threat': bool(prediction),
            'confidence': float(confidence)
        }
    
    def save_model(self, filepath: str):
        """훈련된 모델과 인코더를 디스크에 저장합니다."""
        if not self.is_trained:
            raise ValueError("저장하기 전에 모델을 훈련해야 합니다")
        
        model_data = {
            'model': self.model,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'feature_importance': self.feature_importance_
        }
        
        joblib.dump(model_data, filepath)
        print(f"모델이 {filepath}에 저장되었습니다")
    
    def load_model(self, filepath: str):
        """디스크에서 훈련된 모델과 인코더를 로드합니다."""
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.label_encoders = model_data['label_encoders']
        self.feature_names = model_data['feature_names']
        self.feature_importance_ = model_data['feature_importance']
        self.is_trained = True
        
        print(f"모델이 {filepath}에서 로드되었습니다")
    
    def get_feature_importance(self) -> pd.DataFrame:
        """특성 중요도 분석을 가져옵니다."""
        if not self.is_trained:
            raise ValueError("특성 중요도를 얻으려면 모델을 훈련해야 합니다")
        
        return self.feature_importance_