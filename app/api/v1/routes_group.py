from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID
from app.db.session import get_db
from app.db.models import Group, Settings
from app.schemas.group import GroupCreate
from app.schemas.settings import Settings as SettingsSchema, NotificationWebhookUpdate

router = APIRouter()

@router.get("/groups")
def get_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).all()
    return groups

@router.get("/groups/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group

@router.post("/group")
def create_group(group: GroupCreate, db: Session = Depends(get_db)):
    new_group = Group(**group.model_dump())
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

# Settings (알림 설정) 엔드포인트
@router.get("/groups/{group_id}/settings")
def get_group_settings(group_id: UUID, db: Session = Depends(get_db)):
    """그룹의 알림 설정 조회"""
    settings = db.query(Settings).filter(Settings.group_id == group_id).first()
    if not settings:
        raise HTTPException(status_code=404, detail="Settings not found")
    return settings

@router.post("/groups/{group_id}/settings")
def update_group_settings(
    group_id: UUID,
    settings_data: SettingsSchema,
    db: Session = Depends(get_db)
):
    """그룹의 알림 설정 업데이트"""
    settings = db.query(Settings).filter(Settings.group_id == group_id).first()

    if not settings:
        # Settings가 없으면 새로 생성
        settings = Settings(group_id=group_id)
        db.add(settings)

    # 업데이트할 필드들
    update_data = settings_data.model_dump(exclude_unset=True, exclude={"group_id"})
    for key, value in update_data.items():
        setattr(settings, key, value)

    db.commit()
    db.refresh(settings)
    return settings

@router.post("/groups/{group_id}/settings/notification")
def update_notification_webhooks(
    group_id: UUID,
    notification_data: NotificationWebhookUpdate,
    db: Session = Depends(get_db)
):
    """Discord/Slack Webhook URL 업데이트"""
    settings = db.query(Settings).filter(Settings.group_id == group_id).first()

    if not settings:
        # Settings가 없으면 새로 생성
        settings = Settings(group_id=group_id)
        db.add(settings)

    # 값이 제공된 필드만 업데이트
    update_data = notification_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(settings, key, value)

    db.commit()
    db.refresh(settings)
    return {
        "message": "Notification settings updated successfully",
        "settings": {
            "group_id": str(settings.group_id),
            "discord_webhook_url": settings.discord_webhook_url,
            "slack_webhook_url": settings.slack_webhook_url,
            "notif_enabled": settings.notif_enabled
        }
    }