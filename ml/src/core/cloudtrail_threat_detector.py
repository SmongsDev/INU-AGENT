import pandas as pd
import numpy as np
import json
import joblib
from datetime import datetime
from typing import Dict, List, Union, Tuple, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split, TimeSeriesSplit
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
    # 명확한 Red Team / 공격 도구만 포함 (정상 운영 도구 제외)
    THREAT_TOOLS = frozenset([
        'stratus-red-team', 'stratus', 'atomic-red-team', 'metasploit',
        'nmap', 'sqlmap', 'burp', 'pacu', 'prowler', 'scoutsuite'
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
        
    def extract_features(self, log_event: Dict, previous_events: List[Dict] = None) -> pd.DataFrame:
        """
        단일 CloudTrail 로그 이벤트에서 특성을 추출합니다.

        Args:
            log_event: 딕셔너리 형태의 CloudTrail 로그 이벤트
            previous_events: 현재 이벤트 이전의 이벤트 리스트 (시퀀스 특성 추출용, 선택사항)

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

        # 시퀀스 특성 추가 (previous_events가 제공된 경우)
        if previous_events is not None:
            sequence_features = self._extract_sequence_features(log_event, previous_events)
            features.update(sequence_features)
        else:
            # previous_events가 없을 경우 기본값 설정
            features.update({
                'same_event_count_5min': 0,
                'time_since_last_event_sec': 0,
                'has_stratus_in_1min': False,
                'burst_detected': False,
                'unique_api_count_5min': 0,
                'error_rate_5min': 0.0,
                'session_event_count': 0,
                'user_activity_spike': False
            })

        # DataFrame으로 변환
        df = pd.DataFrame([features])
        return df

    def _extract_sequence_features(self, current_event: Dict, previous_events: List[Dict]) -> Dict:
        """
        이전 이벤트들을 분석하여 시퀀스 기반 특성을 추출합니다.

        Args:
            current_event: 현재 이벤트
            previous_events: 현재 이벤트 이전의 이벤트 리스트

        Returns:
            시퀀스 특성 딕셔너리
        """
        from datetime import datetime, timezone

        sequence_features = {}

        # 이전 이벤트가 없으면 기본값 반환
        if not previous_events:
            return {
                'same_event_count_5min': 0,
                'time_since_last_event_sec': 0,
                'has_stratus_in_1min': False,
                'burst_detected': False,
                'unique_api_count_5min': 0,
                'error_rate_5min': 0.0,
                'session_event_count': len(previous_events),
                'user_activity_spike': False
            }

        # 현재 이벤트 정보
        current_event_name = current_event.get('event_name') or current_event.get('eventName', '')
        current_time_str = current_event.get('event_time') or current_event.get('eventTime', '')

        # 시간 파싱
        try:
            if current_time_str:
                current_time = datetime.fromisoformat(current_time_str.replace('Z', '+00:00'))
            else:
                current_time = datetime.now(timezone.utc)
        except:
            current_time = datetime.now(timezone.utc)

        # 시간 윈도우 설정
        window_5min = 300  # 5분
        window_1min = 60   # 1분

        # 카운터 초기화
        same_event_count = 0
        unique_events = set()
        error_count = 0
        stratus_detected = False
        event_times = []

        # 이전 이벤트 분석
        for prev_event in previous_events:
            prev_event_name = prev_event.get('event_name') or prev_event.get('eventName', '')
            prev_time_str = prev_event.get('event_time') or prev_event.get('eventTime', '')
            prev_user_agent = prev_event.get('user_agent') or prev_event.get('userAgent', '')
            prev_error_code = prev_event.get('error_code') or prev_event.get('errorCode')

            # 시간 파싱
            try:
                if prev_time_str:
                    prev_time = datetime.fromisoformat(prev_time_str.replace('Z', '+00:00'))
                else:
                    continue
            except:
                continue

            time_diff = (current_time - prev_time).total_seconds()

            # 5분 윈도우 내 이벤트 분석
            if 0 <= time_diff <= window_5min:
                # 동일 이벤트 카운트
                if prev_event_name == current_event_name:
                    same_event_count += 1

                # 고유 API 카운트
                unique_events.add(prev_event_name)

                # 에러 카운트
                if prev_error_code:
                    error_count += 1

                # 이벤트 시간 기록 (버스트 감지용)
                event_times.append(time_diff)

            # 1분 윈도우 내 Stratus 탐지
            if 0 <= time_diff <= window_1min:
                if 'stratus' in prev_user_agent.lower():
                    stratus_detected = True

        # 1. 5분내 동일 이벤트 횟수
        sequence_features['same_event_count_5min'] = same_event_count

        # 2. 마지막 이벤트로부터 시간 (초)
        if previous_events:
            last_event_time_str = previous_events[-1].get('event_time') or previous_events[-1].get('eventTime', '')
            try:
                if last_event_time_str:
                    last_event_time = datetime.fromisoformat(last_event_time_str.replace('Z', '+00:00'))
                    sequence_features['time_since_last_event_sec'] = max(0, (current_time - last_event_time).total_seconds())
                else:
                    sequence_features['time_since_last_event_sec'] = 0
            except:
                sequence_features['time_since_last_event_sec'] = 0
        else:
            sequence_features['time_since_last_event_sec'] = 0

        # 3. 1분내 Stratus 도구 사용 여부
        sequence_features['has_stratus_in_1min'] = stratus_detected

        # 4. 버스트 패턴 감지 (10초 내 3개 이상 이벤트)
        burst_window = 10  # 10초
        burst_threshold = 3
        burst_count = sum(1 for t in event_times if t <= burst_window)
        sequence_features['burst_detected'] = burst_count >= burst_threshold

        # 5. 5분내 고유 API 개수
        sequence_features['unique_api_count_5min'] = len(unique_events)

        # 6. 5분내 에러 비율
        total_events_5min = len([t for t in event_times if t <= window_5min])
        if total_events_5min > 0:
            sequence_features['error_rate_5min'] = error_count / total_events_5min
        else:
            sequence_features['error_rate_5min'] = 0.0

        # 7. 세션 전체 이벤트 수
        sequence_features['session_event_count'] = len(previous_events)

        # 8. 사용자 활동 급증 감지 (5분내 10개 이상 이벤트)
        activity_threshold = 10
        sequence_features['user_activity_spike'] = total_events_5min >= activity_threshold

        return sequence_features

    def _create_rule_based_labels(self, logs_data: List[Dict], use_sequence_features: bool = True) -> np.ndarray:
        """
        훈련 데이터를 위한 규칙 기반 라벨을 생성합니다.

        데이터가 적은 상황에서 최소한의 확실한 위협만 탐지하도록 보수적으로 설계됨.

        Args:
            logs_data: CloudTrail 로그 이벤트 리스트 (시간순 정렬 권장)
            use_sequence_features: 시퀀스 특성을 라벨링에 사용할지 여부

        Returns:
            라벨 배열 (1: 위협, 0: 정상)
        """
        labels = []

        for idx, log_event in enumerate(logs_data):
            # 시퀀스 특성 사용 시 이전 이벤트들을 컨텍스트로 전달
            if use_sequence_features and idx > 0:
                # 최근 100개 이벤트를 컨텍스트로 사용
                previous_events = logs_data[max(0, idx-100):idx]
                features_df = self.extract_features(log_event, previous_events=previous_events)
            else:
                features_df = self.extract_features(log_event, previous_events=None)

            features = features_df.iloc[0]

            is_threat = False

            # 규칙 1: Red Team 도구 사용 (가장 확실한 위협)
            # stratus-red-team, metasploit 등의 공격 도구 탐지
            if features['has_threat_tool']:
                is_threat = True

            # 규칙 2: Red Team 관련 리소스 접근 (높은 확신)
            # 'stratus', 'red', 'attack', 'test' 등이 포함된 버킷명
            if features['has_suspicious_resource']:
                is_threat = True

            # 규칙 3: 의심스러운 리소스에 대한 접근 거부
            # Red Team 버킷에 대한 AccessDenied = 공격 시도
            if features['is_access_denied'] and features['has_suspicious_resource']:
                is_threat = True

            # 규칙 4 (완화): 프로그래매틱 + 고위험 액션만으로는 불충분
            # 추가 조건 필요: 비정상 IP 또는 에러 발생
            if (features['is_programmatic'] and
                features['is_high_risk_action'] and
                (not features['is_aws_ip'] and not features['is_internal_ip'])):
                is_threat = True

            # 규칙 5 (강화): 매우 강한 의심 신호가 4개 이상일 때만
            # 정상 운영 활동과의 구분을 위해 임계값 상향
            suspicious_count = sum([
                features['has_error_code'],
                features['is_programmatic'],
                features['is_high_risk_action'],
                features['has_suspicious_resource'],
                not features['is_aws_ip'] and not features['is_internal_ip']
            ])

            if suspicious_count >= 4:
                is_threat = True

            # 규칙 6 (시퀀스 기반): 명확한 공격 패턴 탐지
            if use_sequence_features:
                # 1분 내 Stratus 도구 + 버스트 패턴 = 자동화된 공격
                if features.get('has_stratus_in_1min', False) and features.get('burst_detected', False):
                    is_threat = True

                # 매우 높은 에러율 + 다양한 API 호출 = 무차별 대입 공격 가능성
                if (features.get('error_rate_5min', 0.0) > 0.5 and
                    features.get('unique_api_count_5min', 0) > 10):
                    is_threat = True

                # 활동 급증 + 고위험 액션 = 의심스러운 대량 작업
                if (features.get('user_activity_spike', False) and
                    features['is_high_risk_action']):
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
    
    def extract_features_batch(self, log_events: List[Dict], use_sequence_features: bool = True) -> pd.DataFrame:
        """
        여러 로그 이벤트의 특성을 배치로 추출합니다. (성능 최적화)

        Args:
            log_events: CloudTrail 로그 이벤트 리스트 (시간순 정렬 권장)
            use_sequence_features: 시퀀스 특성 사용 여부 (기본값: True)

        Returns:
            추출된 특성들이 포함된 DataFrame
        """
        if not log_events:
            return pd.DataFrame()

        features_list = []

        for i, log_event in enumerate(log_events):
            # 시퀀스 특성을 사용하는 경우, 이전 이벤트들을 전달
            if use_sequence_features and i > 0:
                # 현재 이벤트 이전의 모든 이벤트를 previous_events로 전달
                # 메모리 효율을 위해 최근 100개만 사용
                previous_events = log_events[max(0, i-100):i]
                features_df = self.extract_features(log_event, previous_events=previous_events)
            else:
                features_df = self.extract_features(log_event, previous_events=None)

            features_list.append(features_df)

        return pd.concat(features_list, ignore_index=True) if features_list else pd.DataFrame()

    def _extract_features_batch_with_context(
        self,
        log_events_with_context: List[Dict],
        start_index: int,
        use_sequence_features: bool = True
    ) -> pd.DataFrame:
        """
        컨텍스트를 포함한 배치에서 특성을 추출합니다.

        Args:
            log_events_with_context: 컨텍스트를 포함한 로그 이벤트 리스트
            start_index: 실제로 특성을 추출할 시작 인덱스
            use_sequence_features: 시퀀스 특성 사용 여부

        Returns:
            추출된 특성들이 포함된 DataFrame
        """
        features_list = []

        for i in range(start_index, len(log_events_with_context)):
            log_event = log_events_with_context[i]

            if use_sequence_features and i > 0:
                previous_events = log_events_with_context[max(0, i-100):i]
                features_df = self.extract_features(log_event, previous_events=previous_events)
            else:
                features_df = self.extract_features(log_event, previous_events=None)

            features_list.append(features_df)

        return pd.concat(features_list, ignore_index=True) if features_list else pd.DataFrame()

    def train(self, logs_data: List[Dict], labels: Optional[np.ndarray] = None, use_sequence_features: bool = True) -> Dict[str, Any]:
        """
        CloudTrail 로그로 Random Forest 모델을 훈련합니다.

        Args:
            logs_data: CloudTrail 로그 이벤트 리스트
            labels: 선택적 라벨 배열. None이면 규칙 기반 라벨링 사용
            use_sequence_features: 시퀀스 특성 사용 여부 (기본값: True)

        Returns:
            성능 지표를 포함한 훈련 결과
        """
        logger.info("로그에서 특성을 추출하는 중...")

        # 시퀀스 특성 사용 시 시간순 정렬
        if use_sequence_features:
            logger.info("시퀀스 특성을 위해 로그를 시간순으로 정렬 중...")
            sorted_logs = sorted(
                logs_data,
                key=lambda x: x.get('event_time') or x.get('eventTime') or '1970-01-01T00:00:00Z'
            )
        else:
            sorted_logs = logs_data

        # 배치 처리로 특성 추출 최적화
        batch_size = 1000
        all_features_list = []

        for i in range(0, len(sorted_logs), batch_size):
            batch = sorted_logs[i:i + batch_size]
            logger.info(f"처리된 로그: {i}/{len(sorted_logs)}")

            # 시퀀스 특성을 위해 이전 배치의 일부를 포함
            if use_sequence_features and i > 0:
                # 이전 100개 이벤트를 포함하여 컨텍스트 제공
                context_start = max(0, i - 100)
                batch_with_context = sorted_logs[context_start:i + batch_size]
                # 배치 특성 추출 (context 포함)
                batch_features = self._extract_features_batch_with_context(
                    batch_with_context,
                    start_index=i - context_start,
                    use_sequence_features=use_sequence_features
                )
            else:
                batch_features = self.extract_features_batch(batch, use_sequence_features=use_sequence_features)

            if not batch_features.empty:
                all_features_list.append(batch_features)

        # 모든 특성 결합
        all_features = pd.concat(all_features_list, ignore_index=True) if all_features_list else pd.DataFrame()
        print(f"추출된 특성 형태: {all_features.shape}")
        
        # 라벨이 제공되지 않은 경우 생성
        if labels is None:
            print("규칙 기반 라벨을 생성하는 중...")
            # 시퀀스 특성을 고려한 라벨링 (sorted_logs 사용)
            labels = self._create_rule_based_labels(sorted_logs, use_sequence_features=use_sequence_features)

        # 특성 준비
        print("범주형 특성을 인코딩하는 중...")
        X = self._prepare_features(all_features, is_training=True)
        y = labels

        self.feature_names = list(X.columns)

        print(f"훈련 데이터 형태: {X.shape}")
        print(f"라벨 분포: {np.bincount(y)}")

        # 시계열 데이터를 위한 분할 (시간순 유지)
        # 전체의 80%를 훈련, 20%를 테스트로 사용
        split_index = int(len(X) * 0.8)
        X_train = X.iloc[:split_index]
        X_test = X.iloc[split_index:]
        y_train = y[:split_index]
        y_test = y[split_index:]

        print(f"훈련 세트 크기: {len(X_train)}, 테스트 세트 크기: {len(X_test)}")

        # 모델 훈련
        print("Random Forest 모델을 훈련하는 중...")
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # 특성 중요도 획득
        self.feature_importance_ = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)

        # 시계열 교차 검증 (TimeSeriesSplit 사용)
        print("시계열 교차 검증을 수행하는 중...")
        tscv = TimeSeriesSplit(n_splits=5)
        cv_scores = cross_val_score(self.model, X, y, cv=tscv, scoring='f1')

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
    
    def _check_definite_threat(self, features: pd.Series) -> Tuple[bool, float, str]:
        """
        확실한 위협 패턴을 규칙 기반으로 체크합니다.

        데이터가 적은 상황에서 ML 모델 예측 전에 명확한 위협을 먼저 탐지합니다.

        Args:
            features: 추출된 특성 (단일 행)

        Returns:
            (is_definite_threat, confidence, reason) 튜플
        """
        # 규칙 1: Red Team 도구 사용 = 확실한 위협
        if features.get('has_threat_tool', False):
            return (True, 0.99, "Red Team tool detected (stratus/metasploit/etc)")

        # 규칙 2: Red Team 관련 리소스 직접 접근 = 확실한 위협
        if features.get('has_suspicious_resource', False):
            return (True, 0.95, "Suspicious resource name (stratus/red/attack/test)")

        # 규칙 3: Red Team 리소스 + AccessDenied = 공격 시도
        if (features.get('is_access_denied', False) and
            features.get('has_suspicious_resource', False)):
            return (True, 0.98, "Access denied on suspicious resource")

        return (False, 0.0, "")

    def predict_batch_with_confidence(self, log_events: List[Dict],
                                       ml_threshold: float = 0.7) -> List[Dict[str, Union[bool, float]]]:
        """
        여러 로그 이벤트에 대해 배치로 예측합니다. (성능 최적화)

        규칙 기반 체크를 먼저 수행한 후 ML 모델로 보조 판단합니다.

        Args:
            log_events: CloudTrail 로그 이벤트 리스트
            ml_threshold: ML 모델 예측 임계값 (기본값: 0.7)

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

        results = []

        # 먼저 규칙 기반 체크 수행
        for i, features in features_df.iterrows():
            is_definite, rule_confidence, rule_reason = self._check_definite_threat(features)

            if is_definite:
                # 확실한 위협은 ML 모델 사용 안 함
                results.append({
                    'is_threat': True,
                    'confidence': rule_confidence,
                    'detection_method': 'rule_based',
                    'reason': rule_reason
                })
            else:
                # ML 모델로 판단 (나중에 일괄 처리)
                results.append(None)

        # ML 모델이 필요한 이벤트만 모아서 배치 처리
        ml_indices = [i for i, r in enumerate(results) if r is None]

        if ml_indices:
            # ML 예측용 특성 준비
            ml_features_df = features_df.iloc[ml_indices]
            X = self._prepare_features(ml_features_df, is_training=False)

            # 배치 예측 수행
            probabilities = self.model.predict_proba(X)

            # ML 결과 적용
            for idx, probs in zip(ml_indices, probabilities):
                threat_prob = probs[1]  # 위협일 확률
                confidence = max(probs)

                # 임계값 적용: ml_threshold 이상일 때만 위협으로 판단
                is_threat = threat_prob >= ml_threshold

                results[idx] = {
                    'is_threat': is_threat,
                    'confidence': float(confidence),
                    'threat_probability': float(threat_prob),
                    'detection_method': 'ml_model',
                    'reason': f"ML prediction (threshold={ml_threshold})"
                }

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