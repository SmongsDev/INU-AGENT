# Discord Webhook URL 설정

## 1. Discord 서버에서 설정:
- Discord 서버 선택
- 채널 설정 (톱니바퀴 아이콘) → "연동" 클릭
- "웹후크" → "새 웹후크" 클릭
- 웹후크 이름 설정 (예: "INU-AGENT 알림")
- "웹후크 URL 복사" 클릭

## 2. URL 형식:
- https://discord.com/api/webhooks/{webhook_id}/{webhook_token}

# Slack Webhook URL 설정

## 1. Slack App 생성:
- https://api.slack.com/apps 접속
- "Create New App" → "From scratch"
- 앱 이름과 워크스페이스 선택
## 2. Incoming Webhooks 활성화:
- 좌측 메뉴에서 "Incoming Webhooks" 클릭
- "Activate Incoming Webhooks" ON
- 하단 "Add New Webhook to Workspace" 클릭
- 알림을 받을 채널 선택
- "Webhook URL" 복사
## 3. URL 형식:
- https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX