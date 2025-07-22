# INU-AGENT

AWS CloudTrail 이벤트를 모니터링하고 분석하는 에이전트 시스템입니다.

## 주요 기능

1. CloudTrail 이벤트 동기화

   - Supabase에 저장된 CloudTrail 이벤트를 주기적으로 동기화
   - 설정 가능한 동기화 주기 (기본값: 5분)
   - 증분 동기화 지원 (마지막 동기화 이후의 새로운 이벤트만 가져옴)

2. 이벤트 분석
   - CloudTrail 이벤트의 자동 분석
   - 의심스러운 활동 탐지
   - 상세한 분석 결과 제공

## 시스템 요구사항

- Python 3.8 이상
- Supabase 계정 및 프로젝트
- 필요한 Python 패키지 (requirements.txt 참조)

## 설치 방법

1. 저장소 클론

```bash
git clone [repository-url]
cd INU-AGENT
```

2. 가상환경 생성 및 활성화

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
.\venv\Scripts\activate  # Windows
```

3. 의존성 설치

```bash
pip install -r requirements.txt
```

## 환경 설정

1. `.env` 파일 생성 및 설정

```
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

2. Supabase 테이블 스키마 설정

```sql
-- 확장 모듈: pgcrypto (UUID 생성용)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- CloudTrail 로그 테이블
CREATE TABLE cloudtrail (
  -- 기본 식별자
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now(),

  -- 이벤트 기본 정보
  event_version TEXT,
  event_time TIMESTAMPTZ,
  event_source TEXT,
  event_name TEXT,
  event_category TEXT,
  event_type TEXT,
  aws_region TEXT,
  read_only BOOLEAN,

  -- 요청/응답 식별자
  request_id TEXT,

  -- 네트워크 정보
  source_ip INET,
  user_agent TEXT,

  -- 관리 및 계정 정보
  management_event BOOLEAN,
  recipient_account_id TEXT,
  session_credential_from_console TEXT,
  shared_event_id TEXT,

  -- 에러 정보
  error_code TEXT,
  error_message TEXT,

  -- JSON 필드
  user_identity JSONB,
  tls_details JSONB,
  request_parameters JSONB,
  response_elements JSONB,
  insight_details JSONB,
  resources JSONB
);
```

## 실행 방법

1. 서버 실행

```bash
uvicorn app.main:app --reload
```

2. 로그 확인

- 콘솔 출력
- `app.log` 파일 (최대 10MB, 5개 백업 파일 유지)

## API 엔드포인트

- `GET /`: 서버 상태 확인
- `POST /analyze-agent`: CloudTrail 이벤트 분석

## 프로젝트 구조

```
INU-AGENT/
├── agents/
│   └── rag/
│       └── supabase_client.py
├── app/
│   ├── api/
│   │   └── routes.py
│   ├── core/
│   │   ├── config.py
│   │   └── logger.py
│   ├── schemas/
│   │   ├── base.py
│   │   └── cloudtrail.py
│   ├── services/
│   │   └── data_sync_service.py
│   └── main.py
├── langgraph_flow/
│   └── nodes/
│       └── analyze.py
└── requirements.txt
```

## 로깅

- 로그 레벨: INFO
- 로그 포맷: `시간 - 로거이름 - 로그레벨 - 메시지`
- 로그 저장: 콘솔 출력 및 파일 저장
- 로그 순환: 10MB 단위, 최대 5개 파일

## 라이선스

[라이선스 정보]
