# INU-AGENT

AWS CloudTrail 이벤트를 모니터링하고 분석하는 AI 기반 에이전트 시스템입니다.

## 🌟 주요 기능

### 1. CloudTrail 이벤트 관리

- 증분 동기화를 통한 효율적인 데이터 관리
- 구조화된 이벤트 데이터 저장 및 관리

### 2. AI 기반 이벤트 분석

- LangGraph를 활용한 고도화된 이벤트 분석
- 의심스러운 활동 자동 탐지
- 상세한 분석 리포트 생성
- RAG(Retrieval Augmented Generation) 기반 컨텍스트 인식 분석

### 3. 사용자 및 그룹 관리

- 역할 기반 접근 제어(RBAC)
- 사용자 그룹 관리
- 상세한 권한 설정

## 🔧 기술 스택

- **Backend**: FastAPI
- **Database**: PostgreSQL
- **AI/ML**: LangGraph, RAG
- **로깅**: Python logging

## 📋 시스템 요구사항

- Python 3.8+
- PostgreSQL 13+
- Supabase 프로젝트
- 필수 Python 패키지 (requirements.txt 참조)

## 🚀 시작하기

### 1. 저장소 클론

```bash
git clone [repository-url]
cd INU-AGENT
```

### 2. 가상환경 설정

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
.\venv\Scripts\activate  # Windows
```

### 3. 의존성 설치

```bash
pip install -r requirements.txt
```

## ⚙️ 환경 설정

1. `.env` 파일 생성

```env
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
DATABASE_URL=your_database_url
LOG_LEVEL=INFO
```

2. 데이터베이스 마이그레이션

```bash
# 마이그레이션 명령어 추가 예정
```

## 📁 프로젝트 구조

```
INU-AGENT/
├── app/                    # 메인 애플리케이션
│   ├── api/               # API 엔드포인트
│   │   └── v1/           # API 버전 1
│   ├── core/             # 핵심 설정 및 유틸리티
│   ├── db/               # 데이터베이스 모델 및 세션
│   ├── schemas/          # Pydantic 스키마
│   └── services/         # 비즈니스 로직
├── langgraph_flow/        # AI 분석 파이프라인
│   ├── nodes/            # 분석 노드
│   │   └── rag/         # RAG 관련 컴포넌트
│   └── graph.py         # 플로우 그래프 정의
├── prompts/              # AI 프롬프트 템플릿
├── tests/               # 테스트 코드
└── docs/                # 문서
```

## 🔄 API 엔드포인트

### 사용자 관리

- `POST /api/v1/users`: 사용자 생성
- `GET /api/v1/users/{user_id}`: 사용자 정보 조회

### 그룹 관리

- `POST /api/v1/groups`: 그룹 생성
- `GET /api/v1/groups/{group_id}`: 그룹 정보 조회

### 이벤트 분석

- `POST /api/v1/analyze`: 이벤트 분석 요청
- `GET /api/v1/analyze/{analysis_id}`: 분석 결과 조회

## 📝 로깅

- **로그 레벨**: 환경 변수로 설정 가능 (기본: INFO)
- **로그 형식**: `시간 - 로거이름 - 로그레벨 - 메시지`
- **저장 방식**:
  - 콘솔 출력
  - 파일 저장 (`logs/app.log`)
  - 로그 순환 (10MB 단위, 최대 5개 파일)

## 🧪 테스트

```bash
# 전체 테스트 실행
pytest

# 특정 모듈 테스트
pytest tests/test_rag_pipeline.py
```

## 🤝 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
